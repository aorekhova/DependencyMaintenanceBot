package com.tungsten.depbot.git;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Real git, real remotes. What matters here is not that {@code fetch} was called but that a branch which
 * was invisible beforehand is visible afterwards -- that is the property an assessment depends on.
 */
class RemoteRefsRefresherTest {

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();
    private final RemoteRefsRefresher refresher = new RemoteRefsRefresher(git);

    @Test
    @DisplayName("a release branch invisible to a single-branch clone becomes visible after the refresh")
    void hiddenReleaseBranchBecomesVisible() throws Exception {
        Path repo = GitTestRepos.createOriginAndSingleBranchClone(tempDir, "release/9.2", "hotfix/9.1.3");

        String before = git.listRefs(repo);
        assertFalse(before.contains("release/9.2"),
                "the clone must start without it, or this test proves nothing: " + before);

        RefsRefreshOutcome outcome = refresher.refresh(repo);

        assertTrue(outcome.refreshed(), outcome.message());
        String after = git.listRefs(repo);
        assertTrue(after.contains("refs/remotes/origin/release/9.2"), after);
        assertTrue(after.contains("refs/remotes/origin/hotfix/9.1.3"), after);
    }

    @Test
    @DisplayName("a branch deleted upstream is pruned, so it can never be chosen as a remediation source")
    void deletedBranchIsPruned() throws Exception {
        Path repo = GitTestRepos.createOriginAndSingleBranchClone(tempDir, "release/9.2");
        refresher.refresh(repo);
        assertTrue(git.listRefs(repo).contains("release/9.2"));

        Path origin = tempDir.resolve("origin.git");
        GitTestRepos.run(origin, "git", "update-ref", "-d", "refs/heads/release/9.2");

        assertTrue(refresher.refresh(repo).refreshed());
        assertFalse(git.listRefs(repo).contains("release/9.2"), git.listRefs(repo));
    }

    @Test
    @DisplayName("tags are refreshed too")
    void tagsAreRefreshed() throws Exception {
        Path repo = GitTestRepos.createOriginAndSingleBranchClone(tempDir);
        Path seed = tempDir.resolve("seed");
        GitTestRepos.run(seed, "git", "tag", "v9.2.0");
        GitTestRepos.run(seed, "git", "push", "-q", "origin", "v9.2.0");

        refresher.refresh(repo);

        assertTrue(git.listRefs(repo).contains("refs/tags/v9.2.0"), git.listRefs(repo));
    }

    @Test
    @DisplayName("an unreachable remote is reported, not thrown -- the refs already present are still real")
    void unreachableRemoteIsReportedNotThrown() throws Exception {
        Path repo = GitTestRepos.createOriginAndSingleBranchClone(tempDir);
        GitTestRepos.run(repo, "git", "remote", "set-url", "origin",
                tempDir.resolve("does-not-exist.git").toString());

        RefsRefreshOutcome outcome = refresher.refresh(repo);

        assertFalse(outcome.refreshed());
        assertTrue(outcome.message().contains("may be out of date"), outcome.message());
        assertTrue(git.listRefs(repo).contains("refs/heads/master"),
                "the repository must still be usable after a failed refresh");
    }
}
