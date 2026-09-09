package com.tungsten.depbot.git;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * The safety primitives around using one checkout for a whole remediation run: is it safe to
 * start, what was there before, switching to a severity's branch, and getting back afterward.
 *
 * <p>Deliberately knows nothing about libraries, Claude, or the diff-policy/commit decision -- see
 * {@code VulnerabilityRemediationService} and {@code RemediationChangeCommitter} for those.
 *
 * <p>Two different levels of trust are at work here, and they force different behaviour.
 * {@link #restoreOriginalState} hands the checkout back to a human once a whole run is over, and never
 * forces anything -- a dirty tree there is left exactly as it is, because by that point this class
 * cannot tell what is safe to discard. {@link #enforceOriginalState}, by contrast, runs entirely inside
 * the bot's own managed run, between one Claude phase and the next; since Claude now has full local git
 * and nothing here relies on it leaving the checkout the way the prompt asked, that method forces
 * whatever it takes -- {@code reset --hard}, {@code clean -fd}, a checkout -- to bring the checkout back
 * to this run's own known baseline before the next step ever sees it.
 */
public final class RemediationCheckoutManager {

    /**
     * Files/directories under {@code .git} that mean a merge, cherry-pick or rebase was left
     * mid-flight. A clean {@code git status} does not rule this out on its own.
     */
    private static final String[] IN_PROGRESS_MARKERS = {
            "MERGE_HEAD", "CHERRY_PICK_HEAD", "rebase-merge", "rebase-apply",
    };

    private final GitCommandRunner git;

    public RemediationCheckoutManager(GitCommandRunner git) {
        this.git = Objects.requireNonNull(git, "git");
    }

    /**
     * @throws DirtyCheckoutException if the working tree is not clean, or a git operation was left
     *                                in progress
     */
    public void verifyCleanAtStart(Path repoPath) {
        for (String marker : IN_PROGRESS_MARKERS) {
            if (Files.exists(repoPath.resolve(".git").resolve(marker))) {
                throw new DirtyCheckoutException(
                        "The repository at " + repoPath + " has an in-progress git operation ("
                                + marker + "). Resolve or abort it before running remediate.");
            }
        }
        if (!git.isClean(repoPath)) {
            throw new DirtyCheckoutException(
                    "The repository at " + repoPath + " has uncommitted changes. Commit, stash, "
                            + "or discard them before running remediate.");
        }
    }

    /**
     * Records the branch (or commit, if detached) the checkout was on before this run touches
     * anything, and anchors it with a dedicated ref so a detached HEAD cannot be garbage-collected
     * away during the run.
     */
    public OriginalState captureOriginalState(Path repoPath, String runId) {
        String branch = git.currentBranch(repoPath);
        String sha = git.currentHeadSha(repoPath);
        boolean detached = "HEAD".equals(branch);
        git.updateRef(repoPath, anchorRef(runId), sha);
        return new OriginalState(detached ? null : branch, sha, detached);
    }

    /** Switches to a remediation branch the orchestrator itself created. */
    public void checkoutBranch(Path repoPath, String branchName) {
        git.checkout(repoPath, branchName);
    }

    /**
     * Detached-HEAD checkout of an exact commit, for a read-only Human Review call. The same underlying
     * git call as {@link #checkoutBranch} -- named separately only so a Human Review call site reads as
     * what it is, not as "checking out a branch." No branch is created and nothing here is ever committed;
     * the caller is expected to restore the original checkout with {@link #enforceOriginalState}
     * immediately after the read-only call returns.
     */
    public void checkoutDetached(Path repoPath, String sha) {
        git.checkout(repoPath, sha);
    }

    /**
     * @deprecated the pre-two-phase name, from when one branch covered a whole severity. Identical to
     *             {@link #checkoutBranch}. Retained only for the legacy
     *             {@code prepare-remediation-branches} command.
     */
    @Deprecated
    public void checkoutSeverityBranch(Path repoPath, String branchName) {
        checkoutBranch(repoPath, branchName);
    }

    /**
     * Forcefully re-establishes {@code original} -- the exact branch (or detached commit) and commit
     * this run started from, with a clean working tree -- regardless of what is currently checked out,
     * staged, or committed. Called after every phase Claude runs: a phase now has full local git, and
     * nothing here relies on it leaving the checkout the way the prompt asked it to. Whatever it
     * actually did -- switched branches, made its own commits, left files modified or untracked -- is
     * undone here, unconditionally, before the orchestrator's next step ever sees the checkout.
     *
     * <p>Unlike {@link #restoreOriginalState}, this never refuses to act. That method hands the
     * checkout back to a human once the whole run is over, so it only ever restores a tree it can
     * already see is clean, and leaves anything else exactly as it is rather than risk it. This method
     * runs entirely within the bot's own managed run, before that handoff -- there is nothing here that
     * needs preserving, only the run's own next step that needs protecting.
     *
     * <p>Whether this succeeded is judged by postcondition, not by the exit code of any one command in
     * the forced sequence: {@code git clean -fd} can report a non-zero exit on Windows/OneDrive
     * checkouts even when it already removed every file it touched, because antivirus or sync software
     * can transiently hold a directory handle open just long enough to make the final, otherwise-empty
     * directory removal fail. Git never tracks empty directories, so a leftover empty directory is
     * invisible to {@code git status --porcelain} -- the checkout can be genuinely clean even though the
     * clean command itself reported failure. So a failure from cleaning untracked files alone is
     * tolerated here, and only turned into a thrown exception if, after the rest of the forced sequence
     * runs, the branch, the commit or the working tree is not actually what {@code original} expects --
     * exactly as before. A failure from any other step in the sequence (the checkout, either reset) is
     * never tolerated, since those touch tracked, committed state rather than files git never tracked in
     * the first place.
     *
     * @throws GitCommandException if even this cannot bring the checkout back -- at that point the
     *                              repository is broken in some way well beyond what a phase could have
     *                              caused on its own, and the run cannot safely continue
     */
    public GitStateEnforcement enforceOriginalState(Path repoPath, OriginalState original) {
        Objects.requireNonNull(repoPath, "repoPath");
        Objects.requireNonNull(original, "original");

        if (isAtExpectedState(repoPath, original)) {
            return GitStateEnforcement.clean();
        }

        String currentBranch = git.currentBranch(repoPath);
        String currentSha = git.currentHeadSha(repoPath);
        String observed = "branch " + currentBranch + " at " + currentSha
                + (git.isClean(repoPath) ? "" : ", with uncommitted changes");

        // Clean whatever is currently checked out first -- a dirty tree would otherwise refuse the
        // checkout below -- then switch to the original ref, then force it to the exact original
        // commit, which is what actually undoes a commit made on that same branch.
        git.resetHard(repoPath, currentSha);

        GitCommandException cleanupFailure = null;
        try {
            git.cleanUntracked(repoPath);
        } catch (GitCommandException e) {
            cleanupFailure = e;
        }

        git.checkout(repoPath, targetRef(original));
        git.resetHard(repoPath, original.headSha());

        if (!isAtExpectedState(repoPath, original)) {
            throw cleanupFailure != null
                    ? cleanupFailure
                    : new GitCommandException(
                            "The checkout could not be confirmed back at " + targetRef(original) + " ("
                                    + original.headSha() + ") after enforcement.");
        }

        String detail = "The checkout was not where this run left it (found " + observed + "); reset to "
                + targetRef(original) + " at " + original.headSha() + " before continuing.";
        if (cleanupFailure != null) {
            detail += " Removing untracked files reported an error (" + cleanupFailure.getMessage()
                    + "), but the checkout is confirmed back at the expected branch, commit and clean "
                    + "state anyway, so that error was not treated as fatal.";
        }
        return GitStateEnforcement.corrected(detail);
    }

    /**
     * Branch (or detached commit), commit and working-tree cleanliness all match {@code original}.
     * {@code git status --porcelain} -- what {@link GitCommandRunner#isClean} checks -- never reports
     * ignored files, so a leftover ignored file or directory (build output, an IDE artifact) can never
     * make this {@code false} on its own; only tracked changes or genuinely untracked, non-ignored
     * content can.
     */
    private boolean isAtExpectedState(Path repoPath, OriginalState original) {
        String currentBranch = git.currentBranch(repoPath);
        String currentSha = git.currentHeadSha(repoPath);
        boolean onExpectedRef = original.detached()
                ? "HEAD".equals(currentBranch)
                : currentBranch.equals(original.branchName());
        boolean atExpectedCommit = currentSha.equals(original.headSha());
        return onExpectedRef && atExpectedCommit && git.isClean(repoPath);
    }

    /**
     * Returns the checkout to {@code original}, but only if it is currently clean. Never forces
     * anything: a dirty tree is reported as unsafe to restore, not overwritten.
     */
    public RestoreOutcome restoreOriginalState(Path repoPath, String runId, OriginalState original) {
        if (!git.isClean(repoPath)) {
            return RestoreOutcome.unsafe(
                    "The checkout at " + repoPath + " is not clean; leaving it as-is rather than "
                            + "risk losing anything. Inspect it manually, then check out "
                            + targetRef(original) + " yourself when ready.");
        }
        try {
            git.checkout(repoPath, targetRef(original));
        } catch (GitCommandException e) {
            return RestoreOutcome.unsafe(
                    "Could not switch back to " + targetRef(original) + ": " + e.getMessage());
        }

        try {
            git.deleteRef(repoPath, anchorRef(runId));
        } catch (GitCommandException e) {
            // The anchor ref is only a safety net against the original commit being garbage
            // collected. The restore itself already succeeded, so a leftover anchor ref is
            // harmless clutter, not a failure to report as unsafe.
        }
        return RestoreOutcome.success();
    }

    private static String targetRef(OriginalState original) {
        return original.detached() ? original.headSha() : original.branchName();
    }

    private static String anchorRef(String runId) {
        return "refs/remediation-bot/original-" + runId;
    }
}
