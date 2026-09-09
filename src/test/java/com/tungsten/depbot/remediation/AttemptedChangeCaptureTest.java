package com.tungsten.depbot.remediation;

import com.tungsten.depbot.claude.ClaudeRunOutcome;
import com.tungsten.depbot.git.ChangeDisposition;
import com.tungsten.depbot.git.ChangeOutcome;
import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.git.GitTestRepos;
import com.tungsten.depbot.implementation.ImplementationOutcome;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fast regression tests for {@link AttemptedChangeCapture} -- the single, unified capture-before-cleanup
 * helper a failed implementation attempt's real changes (committed, or merely left in the working tree,
 * tracked or untracked) must survive through, since the candidate branch/commit is always discarded
 * immediately afterward.
 */
class AttemptedChangeCaptureTest {

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();

    private static ImplementationOutcome outcomeFor(ChangeOutcome change) {
        return new ImplementationOutcome(
                "run1", "unit1", "com.example:artifact", "branch",
                null, change, null, null,
                new ClaudeRunOutcome(true, 0, false, null, List.of(), "start", "end"),
                Path.of("implementation-dir"), null, java.util.Map.of());
    }

    private static ChangeOutcome committed(String commitSha) {
        return new ChangeOutcome(ChangeDisposition.COMMITTED_PENDING_VALIDATION, commitSha, "", List.of(), "kept", null);
    }

    private static ChangeOutcome rolledBack() {
        return new ChangeOutcome(ChangeDisposition.ROLLED_BACK, null, "", List.of(), "rolled back", null);
    }

    private static ChangeOutcome rolledBackWithPatch(String patch) {
        return new ChangeOutcome(ChangeDisposition.ROLLED_BACK, null, patch, List.of(), "rolled back", null);
    }

    @Test
    @DisplayName("a committed change is captured via diffBinary against the accepted base SHA")
    void committedChangeUsesDiffBinary() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseSha = git.currentHeadSha(work);
        Files.writeString(work.resolve("file.txt"), "changed-and-committed\n", StandardCharsets.UTF_8);
        git.add(work);
        git.commit(work, "attempted change");
        String commitSha = git.currentHeadSha(work);

        String patch = AttemptedChangeCapture.capturePatch(git, work, baseSha, outcomeFor(committed(commitSha)));

        assertNotNull(patch);
        assertEquals(git.diffBinary(work, baseSha, commitSha), patch);
        assertTrue(patch.contains("changed-and-committed"), patch);
    }

    @Test
    @DisplayName("no commit, but a dirty tracked working tree, is captured via diffWorkingTreeAgainst")
    void noCommitDirtyTrackedTreeUsesWorkingTreeDiff() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseSha = git.currentHeadSha(work);
        Files.writeString(work.resolve("file.txt"), "changed-but-not-committed\n", StandardCharsets.UTF_8);

        String patch = AttemptedChangeCapture.capturePatch(git, work, baseSha, outcomeFor(rolledBack()));

        assertNotNull(patch);
        assertTrue(patch.contains("changed-but-not-committed"), patch);
    }

    @Test
    @DisplayName("a rolled-back attempt whose ChangeOutcome already carries a captured patch is used "
            + "directly, even though RemediationChangeCommitter has already reset and cleaned the working "
            + "tree by the time capturePatch runs -- this is the real STOPPED_BLOCKED / "
            + "STOPPED_PLAN_DEVIATION_REQUIRED / PlanConformanceGate-rejection case, and a git-based "
            + "re-derivation alone would find nothing here")
    void rolledBackOutcomeWithCapturedPatchIsUsedDirectlyEvenAfterTreeIsAlreadyClean() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseSha = git.currentHeadSha(work);

        // Simulate exactly what RemediationChangeCommitter does: capture the diff (including a brand-new
        // untracked file, via its own full `git add`, not intent-to-add), THEN reset/clean back to
        // baseline before implement() ever returns.
        Files.writeString(work.resolve("file.txt"), "attempted-but-rolled-back\n", StandardCharsets.UTF_8);
        Files.writeString(work.resolve("new-file.txt"), "also-rolled-back\n", StandardCharsets.UTF_8);
        git.add(work);
        String realPatch = git.diffCached(work);
        git.resetHard(work, baseSha);
        git.cleanUntracked(work);
        assertTrue(git.isClean(work), "the working tree must already be clean, mirroring the real rollback timing");

        String patch = AttemptedChangeCapture.capturePatch(git, work, baseSha, outcomeFor(rolledBackWithPatch(realPatch)));

        assertEquals(realPatch, patch);
        assertTrue(patch.contains("attempted-but-rolled-back"), patch);
        assertTrue(patch.contains("new-file.txt"), patch);
    }

    @Test
    @DisplayName("no commit and a clean working tree captures nothing")
    void noCommitCleanTreeCapturesNull() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseSha = git.currentHeadSha(work);

        String patch = AttemptedChangeCapture.capturePatch(git, work, baseSha, outcomeFor(rolledBack()));

        assertNull(patch);
    }

    @Test
    @DisplayName("a tracked modification plus a brand-new untracked file are captured, cleaned up, and "
            + "git apply reproduces the exact attempted state byte for byte")
    void trackedModificationAndUntrackedFileSurviveCleanupViaGitApply() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseSha = git.currentHeadSha(work);

        Files.writeString(work.resolve("file.txt"), "tracked-mod\n", StandardCharsets.UTF_8);
        Files.writeString(work.resolve("new-untracked-file.txt"), "brand-new-content\n", StandardCharsets.UTF_8);

        String patch = AttemptedChangeCapture.capturePatch(git, work, baseSha, outcomeFor(rolledBack()));
        assertNotNull(patch);
        assertTrue(patch.contains("tracked-mod"), "must include the tracked modification: " + patch);
        assertTrue(patch.contains("new-untracked-file.txt"), "must include the untracked file's path: " + patch);
        assertTrue(patch.contains("brand-new-content"), "must include the untracked file's content: " + patch);

        // Cleanup, exactly as attemptGroup would do right after capture: discard everything, back to base.
        git.resetHard(work, baseSha);
        git.cleanUntracked(work);
        assertTrue(git.isClean(work));
        assertEquals(baseSha, git.currentHeadSha(work));
        assertTrue(!Files.exists(work.resolve("new-untracked-file.txt")),
                "the untracked file must genuinely be gone after cleanup, proving capture happened first");

        Path patchFile = tempDir.resolve("attempted.patch");
        Files.writeString(patchFile, patch, StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "apply", patchFile.toAbsolutePath().toString());

        assertEquals("tracked-mod\n", Files.readString(work.resolve("file.txt"), StandardCharsets.UTF_8),
                "git apply must reproduce the tracked modification exactly");
        assertEquals("brand-new-content\n",
                Files.readString(work.resolve("new-untracked-file.txt"), StandardCharsets.UTF_8),
                "git apply must reproduce the new file exactly, proving the untracked file was never lost");
    }
}
