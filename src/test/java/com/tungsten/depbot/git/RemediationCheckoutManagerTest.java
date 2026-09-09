package com.tungsten.depbot.git;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemediationCheckoutManagerTest {

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();
    private final RemediationCheckoutManager manager = new RemediationCheckoutManager(git);

    @Test
    @DisplayName("verifyCleanAtStart does not throw on a clean checkout")
    void verifyCleanAtStartAllowsCleanCheckout() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        manager.verifyCleanAtStart(work);
    }

    @Test
    @DisplayName("verifyCleanAtStart throws when the working tree has uncommitted changes")
    void verifyCleanAtStartRejectsDirtyTree() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve("file.txt"), "changed\n", StandardCharsets.UTF_8);

        assertThrows(DirtyCheckoutException.class, () -> manager.verifyCleanAtStart(work));
    }

    @Test
    @DisplayName("verifyCleanAtStart throws when a merge is left in progress, even with a clean status")
    void verifyCleanAtStartRejectsInProgressMerge() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve(".git").resolve("MERGE_HEAD"),
                git.currentHeadSha(work) + "\n", StandardCharsets.UTF_8);

        assertTrue(git.isClean(work), "status is clean even though a merge marker exists");
        assertThrows(DirtyCheckoutException.class, () -> manager.verifyCleanAtStart(work));
    }

    @Test
    @DisplayName("verifyCleanAtStart throws when a rebase is left in progress")
    void verifyCleanAtStartRejectsInProgressRebase() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.createDirectories(work.resolve(".git").resolve("rebase-merge"));

        assertThrows(DirtyCheckoutException.class, () -> manager.verifyCleanAtStart(work));
    }

    @Test
    @DisplayName("capture and restore return an attached branch to exactly where it was")
    void captureAndRestoreAttachedBranch() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String sha = git.currentHeadSha(work);
        git.createBranch(work, "remediation/run1/critical", sha);

        OriginalState original = manager.captureOriginalState(work, "run1");
        assertEquals("master", original.branchName());
        assertFalse(original.detached());

        manager.checkoutSeverityBranch(work, "remediation/run1/critical");
        assertEquals("remediation/run1/critical", git.currentBranch(work));

        RestoreOutcome outcome = manager.restoreOriginalState(work, "run1", original);

        assertTrue(outcome.restored());
        assertEquals("master", git.currentBranch(work));
    }

    @Test
    @DisplayName("capture and restore return a detached HEAD to exactly the same commit, still detached")
    void captureAndRestoreDetachedHead() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String sha = git.currentHeadSha(work);
        git.checkout(work, sha);
        git.createBranch(work, "remediation/run1/critical", sha);

        OriginalState original = manager.captureOriginalState(work, "run1");
        assertTrue(original.detached());
        assertEquals(sha, original.headSha());

        manager.checkoutSeverityBranch(work, "remediation/run1/critical");
        RestoreOutcome outcome = manager.restoreOriginalState(work, "run1", original);

        assertTrue(outcome.restored());
        assertEquals("HEAD", git.currentBranch(work));
        assertEquals(sha, git.currentHeadSha(work));
    }

    @Test
    @DisplayName("restoreOriginalState reports unsafe, without forcing anything, when the tree is dirty")
    void restoreReportsUnsafeWithoutForcingWhenDirty() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        OriginalState original = manager.captureOriginalState(work, "run1");
        Files.writeString(work.resolve("file.txt"), "left dirty\n", StandardCharsets.UTF_8);

        RestoreOutcome outcome = manager.restoreOriginalState(work, "run1", original);

        assertFalse(outcome.restored());
        assertTrue(outcome.safeMessage() != null && !outcome.safeMessage().isBlank());
        assertEquals("left dirty\n", Files.readString(work.resolve("file.txt"), StandardCharsets.UTF_8),
                "the dirty content must be left exactly as it was, never discarded");
    }

    @Test
    @DisplayName("the anchor ref is removed after a successful restore")
    void anchorRefIsRemovedAfterSuccessfulRestore() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        OriginalState original = manager.captureOriginalState(work, "run1");

        assertEquals(original.headSha(), git.revParse(work, "refs/remediation-bot/original-run1"));

        manager.restoreOriginalState(work, "run1", original);

        assertThrows(GitCommandException.class,
                () -> git.revParse(work, "refs/remediation-bot/original-run1"));
    }

    // ---- enforceOriginalState ---------------------------------------------------------------

    @Test
    @DisplayName("enforceOriginalState reports clean without touching anything when already as expected")
    void enforceOriginalStateReportsCleanWhenAlreadyAsExpected() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        OriginalState original = manager.captureOriginalState(work, "run1");

        GitStateEnforcement result = manager.enforceOriginalState(work, original);

        assertTrue(result.wasAsExpected());
    }

    @Test
    @DisplayName("enforceOriginalState forces an untracked file, a branch switch and a stray commit back "
            + "to the original branch and commit when cleanup succeeds normally")
    void enforceOriginalStateForcesBackToBaselineWhenCleanupSucceeds() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        OriginalState original = manager.captureOriginalState(work, "run1");

        git.createBranch(work, "other", original.headSha());
        git.checkout(work, "other");
        Files.writeString(work.resolve("committed.txt"), "on other\n", StandardCharsets.UTF_8);
        git.add(work);
        git.commit(work, "stray commit made on the wrong branch");
        Files.writeString(work.resolve("stray.txt"), "left behind, untracked\n", StandardCharsets.UTF_8);

        GitStateEnforcement result = manager.enforceOriginalState(work, original);

        assertFalse(result.wasAsExpected());
        assertTrue(result.detail() != null && !result.detail().isBlank());
        assertEquals("master", git.currentBranch(work));
        assertEquals(original.headSha(), git.currentHeadSha(work));
        assertTrue(git.isClean(work));
    }

    @Test
    @DisplayName("enforceOriginalState tolerates a cleanUntracked failure when the checkout is confirmed "
            + "back at the expected branch, commit and clean state anyway")
    void enforceOriginalStateToleratesCleanupFailureWhenPostconditionsHold() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        RemediationCheckoutManager toleratingManager =
                new RemediationCheckoutManager(new AlwaysFailingCleanGitCommandRunner());
        OriginalState original = toleratingManager.captureOriginalState(work, "run1");

        git.createBranch(work, "other", original.headSha());
        git.checkout(work, "other");
        // No untracked content left behind: a real "git clean -fd" here would have been a no-op even
        // though it is about to be simulated as failing anyway, matching the Windows/OneDrive shape
        // where the command reports an error despite nothing actually being left uncleaned.

        GitStateEnforcement result = toleratingManager.enforceOriginalState(work, original);

        assertFalse(result.wasAsExpected());
        assertTrue(result.detail().contains("was not treated as fatal"), result.detail());
        assertEquals("master", git.currentBranch(work));
        assertEquals(original.headSha(), git.currentHeadSha(work));
        assertTrue(git.isClean(work));
    }

    @Test
    @DisplayName("enforceOriginalState still fails closed when a cleanUntracked failure is tolerated but "
            + "the working tree is genuinely left dirty afterward")
    void enforceOriginalStateFailsClosedWhenPostconditionsAreStillViolated() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        RemediationCheckoutManager toleratingManager =
                new RemediationCheckoutManager(new AlwaysFailingCleanGitCommandRunner());
        OriginalState original = toleratingManager.captureOriginalState(work, "run1");

        git.createBranch(work, "other", original.headSha());
        git.checkout(work, "other");
        Files.writeString(work.resolve("stray-untracked.txt"), "never cleaned\n", StandardCharsets.UTF_8);

        assertThrows(GitCommandException.class,
                () -> toleratingManager.enforceOriginalState(work, original));
        // The forced sequence still ran as far as it could -- branch and commit are back, only the
        // fake clean failure's leftover untracked file keeps the tree from being confirmed clean.
        assertEquals("master", git.currentBranch(work));
        assertEquals(original.headSha(), git.currentHeadSha(work));
    }

    @Test
    @DisplayName("enforceOriginalState is not tripped up by a leftover ignored file: it is invisible to "
            + "git status --porcelain and was never a target of git clean -fd in the first place")
    void enforceOriginalStateIgnoresLeftoverIgnoredContent() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve(".gitignore"), "ignored-dir/\n", StandardCharsets.UTF_8);
        git.add(work);
        git.commit(work, "add gitignore");
        OriginalState original = manager.captureOriginalState(work, "run1");

        git.createBranch(work, "other", original.headSha());
        git.checkout(work, "other");
        Files.createDirectories(work.resolve("ignored-dir"));
        Files.writeString(work.resolve("ignored-dir").resolve("leftover.txt"), "irrelevant\n",
                StandardCharsets.UTF_8);

        GitStateEnforcement result = manager.enforceOriginalState(work, original);

        assertFalse(result.wasAsExpected());
        assertEquals("master", git.currentBranch(work));
        assertEquals(original.headSha(), git.currentHeadSha(work));
        assertTrue(git.isClean(work));
        assertTrue(Files.exists(work.resolve("ignored-dir").resolve("leftover.txt")),
                "git clean -fd (without -x) must never remove ignored content");
    }

    /** Simulates the Windows/OneDrive shape: {@code git clean -fd} always reports a non-zero exit. */
    private static final class AlwaysFailingCleanGitCommandRunner extends GitCommandRunner {
        @Override
        public void cleanUntracked(Path repoDirectory) {
            throw new GitCommandException(
                    "\"git clean -fd\" failed (exit 1) in " + repoDirectory
                            + ": error: unable to rmdir 'stray-dir': Permission denied");
        }
    }
}
