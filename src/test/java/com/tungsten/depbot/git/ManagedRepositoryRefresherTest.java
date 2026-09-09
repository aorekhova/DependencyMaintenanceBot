package com.tungsten.depbot.git;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ManagedRepositoryRefresher} against a real git repository -- proving the managed checkout is
 * genuinely synchronized to its verified remote counterpart before remediation ever begins, and that a
 * dirty tree, a detached HEAD, or an unsafe local divergence all fail closed rather than being silently
 * discarded by a destructive reset.
 */
class ManagedRepositoryRefresherTest {

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();
    private Path repo;

    @BeforeEach
    void setUp() throws Exception {
        repo = GitTestRepos.createOriginAndClone(tempDir);
    }

    private ManagedRepositoryRefresher refresher() {
        return new ManagedRepositoryRefresher(git, new SourceRefVerifier(git));
    }

    private OriginalState originalOnMaster() {
        return new OriginalState("master", git.currentHeadSha(repo), false);
    }

    @Test
    @DisplayName("a clean checkout that is purely behind origin is fast-forwarded to the verified remote tip")
    void cleanBehindCheckoutIsFastForwardedToVerifiedTip() throws Exception {
        OriginalState original = originalOnMaster();

        // A second clone advances origin/master with a new commit this checkout has not seen yet.
        Path secondClone = tempDir.resolve("second-clone");
        GitTestRepos.run(tempDir, "git", "clone", "-q", tempDir.resolve("origin.git").toString(), secondClone.toString());
        GitTestRepos.run(secondClone, "git", "config", "user.email", "test@example.com");
        GitTestRepos.run(secondClone, "git", "config", "user.name", "test");
        Files.writeString(secondClone.resolve("advanced.txt"), "advanced\n", StandardCharsets.UTF_8);
        GitTestRepos.run(secondClone, "git", "add", "-A");
        GitTestRepos.run(secondClone, "git", "commit", "-q", "-m", "advance origin");
        GitTestRepos.run(secondClone, "git", "push", "-q", "origin", "master");
        String advancedSha = GitTestRepos.shaOf(secondClone, "master");

        // This checkout only learns about it once its own remote-tracking ref is refreshed -- exactly
        // what RemoteRefsRefresher already does, immediately before this class runs in production.
        GitTestRepos.run(repo, "git", "fetch", "-q", "origin");

        RepositoryRefreshOutcome outcome = refresher().refresh(repo, original);

        assertTrue(outcome.refreshed(), outcome.message());
        assertEquals(advancedSha, outcome.verifiedSourceSha());
        assertEquals(advancedSha, git.currentHeadSha(repo));
        assertTrue(git.isClean(repo));
    }

    @Test
    @DisplayName("a detached HEAD fails closed -- there is no branch to refresh against")
    void detachedHeadFailsClosed() {
        OriginalState detached = new OriginalState(null, git.currentHeadSha(repo), true);

        RepositoryRefreshOutcome outcome = refresher().refresh(repo, detached);

        assertFalse(outcome.refreshed());
    }

    @Test
    @DisplayName("a dirty working tree fails closed, and the uncommitted file is never touched")
    void dirtyWorkingTreeFailsClosedWithoutDestroyingAnything() throws Exception {
        Files.writeString(repo.resolve("uncommitted.txt"), "do not lose me\n", StandardCharsets.UTF_8);
        OriginalState original = originalOnMaster();

        RepositoryRefreshOutcome outcome = refresher().refresh(repo, original);

        assertFalse(outcome.refreshed());
        assertTrue(Files.exists(repo.resolve("uncommitted.txt")),
                "a dirty tree must never be discarded by this step");
        assertEquals("do not lose me\n",
                Files.readString(repo.resolve("uncommitted.txt"), StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("a local commit that has diverged from origin (not an ancestor of it) fails closed -- "
            + "reset --hard is never used to silently discard it")
    void divergedLocalCommitFailsClosedRatherThanBeingDiscarded() throws Exception {
        // A commit made directly on this managed checkout, never pushed anywhere -- origin/master's own
        // remote-tracking ref still points at the commit this local one was built on top of, so the
        // local HEAD is not an ancestor of (nor equal to) the verified remote tip.
        Files.writeString(repo.resolve("local-only.txt"), "never pushed\n", StandardCharsets.UTF_8);
        GitTestRepos.run(repo, "git", "add", "-A");
        GitTestRepos.run(repo, "git", "commit", "-q", "-m", "a stray local commit");
        String divergedSha = git.currentHeadSha(repo);
        OriginalState original = new OriginalState("master", divergedSha, false);

        RepositoryRefreshOutcome outcome = refresher().refresh(repo, original);

        assertFalse(outcome.refreshed(), "a diverged local commit must never be silently reset away");
        assertTrue(outcome.message().contains("diverged"), outcome.message());
        // The local commit is still exactly where it was -- nothing was reset.
        assertEquals(divergedSha, git.currentHeadSha(repo));
        assertTrue(Files.exists(repo.resolve("local-only.txt")));
    }
}
