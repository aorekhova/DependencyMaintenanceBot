package com.tungsten.depbot.git;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Decides whether an implementation's changes are kept, and carries out the git operations either way.
 *
 * <p><strong>Staging and committing belong here and nowhere else, in outcome if not in tool
 * permission.</strong> Claude has full local git -- {@code commit}, {@code checkout}, {@code branch}
 * included -- the implementation prompt asks it to stay on the branch prepared for it and leave the
 * remediation as uncommitted edits for this class to stage and commit, but that is a request, not a
 * restriction the tool enforces. So this class does not assume either was honoured. Two different
 * failure shapes get two deliberately different responses. A commit made on the <em>expected</em>
 * branch is reconciled by {@link #reconcileAnySelfMadeCommits}: its content is known to belong to this
 * remediation (nothing else could have put it on that branch), so it is folded back into an ordinary
 * unstaged diff and reviewed exactly like any other change. Ending up on a <em>different</em> branch
 * (or detached) is not reconciled at all -- {@link #checkWrongBranch} fails closed instead, because a
 * branch Claude merely switched to can carry its own pre-existing content that has nothing to do with
 * this remediation, and there is no reliable way to tell the two apart from the outside. Nothing found
 * on the wrong branch is ever staged, diffed or committed; the run is told a human is needed instead.
 *
 * <p>Three independent conditions must all hold for a commit. The implementation must have reported that
 * it actually completed the remediation -- an agent that stopped because the branch contradicted the
 * assessment may still have edited something before it stopped, and that partial work must not be kept.
 * The resulting diff must pass {@link RemediationDiffPolicy}, checked once before the orchestrator stages
 * anything and again against the fully staged diff. And nothing else may have refused it: the caller
 * passes in the local validation gate's objection, if it had one. Anything else is rolled back to the
 * branch tip the implementation started from, which leaves any earlier commit on that branch untouched.
 *
 * <p>Unlike the diff-policy check itself, nothing here inspects what kind of files changed. A security
 * remediation may legitimately need to touch build configuration, a BOM, Java sources, tests, resources,
 * generated metadata or a related dependency, and which of those a given fix requires is not knowable in
 * advance. The policy screens for the handful of things that are wrong regardless of the fix; the scope
 * of the change itself is the assessment's and the reviewer's judgement, not a rule enforced here.
 */
public final class RemediationChangeCommitter {

    private final GitCommandRunner git;
    private final RemediationDiffPolicy diffPolicy;

    public RemediationChangeCommitter(GitCommandRunner git, RemediationDiffPolicy diffPolicy) {
        this.git = Objects.requireNonNull(git, "git");
        this.diffPolicy = Objects.requireNonNull(diffPolicy, "diffPolicy");
    }

    /** As {@link #finalizeChange(Path, String, String, boolean, String, String, List)}, with nothing else
     *  refusing and no known baseline untracked-file snapshot (see that overload). */
    public ChangeOutcome finalizeChange(
            Path repoPath, String expectedBranch, String baselineSha, boolean workCompleted,
            String commitMessage) {
        return finalizeChange(repoPath, expectedBranch, baselineSha, workCompleted, null, commitMessage, List.of());
    }

    /**
     * @param expectedBranch          the remediation branch the orchestrator created and checked out for
     *                                this implementation -- the branch its result must end up on,
     *                                whatever Claude actually did with git along the way
     * @param baselineSha             the branch tip before the implementation ran -- the rollback target
     * @param workCompleted           whether the implementation reported carrying the remediation
     *                                through; false for a failed call, an unreadable report, or a
     *                                deliberate safe stop
     * @param refusalReason           a reason the change must not be kept even though it was reported
     *                                complete -- the local validation gate's verdict -- or {@code null}
     *                                when nothing else objects. Carried in rather than decided here
     *                                because what counts as adequate validation is a policy question, and
     *                                this class is only the git half of it
     * @param commitMessage           used only if the change is kept
     * @param baselineUntrackedFiles  every untracked file already present in {@code repoPath} before this
     *                                attempt began (see {@link GitCommandRunner#listUntrackedFiles}) --
     *                                what a rollback must never delete, however it got there. An empty
     *                                list is treated as "nothing pre-existing," never as "delete
     *                                everything": callers that genuinely have no such snapshot (the
     *                                5-argument overload) get the safest reading, not the most permissive.
     * @throws GitCommandException if staging or committing itself fails, or if a rollback cannot actually
     *                             confirm the working tree back at {@code baselineSha} with every
     *                             attempt-created untracked path gone -- see {@link #rollback}
     */
    public ChangeOutcome finalizeChange(
            Path repoPath, String expectedBranch, String baselineSha, boolean workCompleted,
            String refusalReason, String commitMessage, List<String> baselineUntrackedFiles) {
        Objects.requireNonNull(repoPath, "repoPath");
        Objects.requireNonNull(expectedBranch, "expectedBranch");
        Objects.requireNonNull(baselineSha, "baselineSha");
        Set<String> baselineUntracked = baselineUntrackedFiles == null
                ? Set.of() : new LinkedHashSet<>(baselineUntrackedFiles);
        boolean refused = refusalReason != null && !refusalReason.isBlank();

        ChangeOutcome wrongBranchOutcome = checkWrongBranch(repoPath, expectedBranch, baselineSha, baselineUntracked);
        if (wrongBranchOutcome != null) {
            return wrongBranchOutcome;
        }

        reconcileAnySelfMadeCommits(repoPath, baselineSha);

        if (git.isClean(repoPath)) {
            // Nothing was touched. There is no diff to check, nothing to stage, and a commit git would
            // refuse anyway -- so this is neither a commit nor an undo.
            return new ChangeOutcome(ChangeDisposition.NO_CHANGES, null, "", List.of(),
                    workCompleted
                            ? "The implementation reported completion but changed nothing."
                            : "The implementation stopped without changing anything.", null);
        }

        List<String> violations = new ArrayList<>();
        PolicyVerdict beforeStaging = diffPolicy.checkBeforeStaging(repoPath, git);
        violations.addAll(beforeStaging.violations());

        PolicyVerdict afterStaging = PolicyVerdict.passed();
        if (beforeStaging.allowed()) {
            git.add(repoPath);
            afterStaging = diffPolicy.checkStagedDiff(repoPath, git);
            violations.addAll(afterStaging.violations());
        }

        String patch = git.diffCached(repoPath);
        boolean policyAllowed = beforeStaging.allowed() && afterStaging.allowed();

        if (workCompleted && policyAllowed && !refused) {
            git.commit(repoPath, commitMessage);
            return new ChangeOutcome(ChangeDisposition.COMMITTED_PENDING_VALIDATION,
                    git.currentHeadSha(repoPath), patch, List.of(),
                    "Committed on the remediation branch; nothing has compiled or tested it yet.", null);
        }

        rollback(repoPath, baselineSha, baselineUntracked);

        String reason = rollbackReason(workCompleted, policyAllowed, refusalReason, violations);
        return new ChangeOutcome(ChangeDisposition.ROLLED_BACK, null, patch, violations, reason, null);
    }

    /**
     * Resets the working tree to {@code baselineSha}, then removes only the untracked files this attempt
     * itself created since {@code baselineUntrackedFiles} was captured -- never an indiscriminate
     * {@code git clean -fd} across the whole repository (production incident, pilot
     * {@code 20260908-220923-771c06}: two rollbacks each reported {@code git clean -fd failed} with
     * {@code Permission denied} against {@code .settings} and other pre-existing, unrelated untracked
     * directories nothing here has any business touching).
     *
     * <p>An emptied parent directory left behind by one of those deletions is removed too, exactly the
     * way {@code git clean -fd} would have -- but only ever a directory this method's own deletions just
     * emptied, never a pre-existing empty one. A directory that fails to delete (a transient
     * Windows/OneDrive lock, exactly like the antivirus/sync scenario the old {@code git clean -fd}
     * comment described) is silently left in place: git never tracks empty directories, so this can never
     * make the working tree fail its own clean-relative-to-baseline check below.
     *
     * @throws GitCommandException if an attempt-created untracked file could not be removed, or if the
     *                              working tree is not confirmed back at {@code baselineSha} with no
     *                              attempt-created untracked path remaining afterward -- a rollback that
     *                              cannot prove this must fail loudly, never return a quiet, possibly
     *                              contaminated {@code ROLLED_BACK} outcome
     */
    private void rollback(Path repoPath, String baselineSha, Set<String> baselineUntrackedFiles) {
        git.resetHard(repoPath, baselineSha);

        GitCommandException cleanupFailure = null;
        try {
            removeAttemptCreatedUntrackedFiles(repoPath, baselineUntrackedFiles);
        } catch (GitCommandException e) {
            cleanupFailure = e;
        }

        if (!confirmedCleanRelativeToBaseline(repoPath, baselineSha, baselineUntrackedFiles)) {
            throw cleanupFailure != null ? cleanupFailure
                    : new GitCommandException("Rollback could not confirm the working tree back at "
                            + baselineSha + " with no attempt-created untracked path remaining.");
        }
    }

    /**
     * Deletes exactly the untracked files present now that were not already present at
     * {@code baselineUntrackedFiles} -- a pre-existing untracked path is never this attempt's to remove,
     * whatever it is or however it got there.
     *
     * @throws GitCommandException naming every attempt-created untracked path that could not be removed
     */
    private void removeAttemptCreatedUntrackedFiles(Path repoPath, Set<String> baselineUntrackedFiles) {
        List<String> undeleted = new ArrayList<>();
        for (String relativePath : git.listUntrackedFiles(repoPath)) {
            if (baselineUntrackedFiles.contains(relativePath)) {
                continue;
            }
            Path file = repoPath.resolve(relativePath);
            try {
                Files.deleteIfExists(file);
                deleteNowEmptyParents(repoPath, file.getParent());
            } catch (IOException e) {
                undeleted.add(relativePath);
            }
        }
        if (!undeleted.isEmpty()) {
            throw new GitCommandException("Could not remove untracked file(s) this attempt created: "
                    + undeleted);
        }
    }

    /** Removes {@code directory} and each parent above it, stopping at the first that is not empty, does
     *  not exist, or cannot be removed -- never a pre-existing empty directory this attempt did not just
     *  empty itself, and never {@code repoRoot} itself. */
    private static void deleteNowEmptyParents(Path repoRoot, Path directory) {
        Path current = directory;
        while (current != null && !current.equals(repoRoot)) {
            try (Stream<Path> children = Files.list(current)) {
                if (children.findAny().isPresent()) {
                    return;
                }
            } catch (IOException e) {
                return;
            }
            try {
                Files.delete(current);
            } catch (IOException e) {
                return;
            }
            current = current.getParent();
        }
    }

    /**
     * Whether the working tree is genuinely back at {@code baselineSha}: no tracked difference, and no
     * untracked path beyond what {@code baselineUntrackedFiles} already had. A pre-existing untracked
     * path is expected and is never itself evidence that a rollback failed.
     */
    private boolean confirmedCleanRelativeToBaseline(
            Path repoPath, String baselineSha, Set<String> baselineUntrackedFiles) {
        if (!git.currentHeadSha(repoPath).equals(baselineSha)) {
            return false;
        }
        for (String line : git.status(repoPath).lines().toList()) {
            if (line.isBlank()) {
                continue;
            }
            if (!line.startsWith("??")) {
                return false; // a tracked difference remains
            }
            if (!baselineUntrackedFiles.contains(line.substring(2).strip())) {
                return false; // an untracked path beyond this attempt's own baseline remains
            }
        }
        return true;
    }

    /**
     * Fails closed when the implementation did not finish on {@code expectedBranch}.
     *
     * <p>Claude now has full local git, including {@code checkout}, {@code switch} and {@code branch},
     * and can end a call anywhere. An earlier version of this class tried to recover such a case by
     * transplanting the complete working-tree state onto the remediation branch; that was withdrawn as
     * too risky, because a branch Claude merely switched to -- an existing one, or a brand new one -- can
     * carry its own pre-existing uncommitted or committed content that has nothing to do with this
     * remediation at all, and a blind tree transplant cannot tell the two apart from the outside.
     *
     * <p>So instead: nothing found on the wrong branch is ever inspected for a diff, staged, or
     * committed. Whatever is there -- uncommitted edits, a commit Claude made, or both -- is left exactly
     * where it is; this method only discards the wrong branch's own uncommitted state (never its commit
     * history) so the checkout can move safely, then forces the checkout back onto
     * {@code expectedBranch} at {@code baselineSha}, exactly where the implementation started. The
     * result is reported as needing a human, with the actual branch and commit Claude left named
     * plainly, so a human knows where to look without the bot itself guessing which of the changes it
     * found belong to this remediation.
     *
     * @return the outcome to return from {@link #finalizeChange}, or {@code null} if the checkout was
     *         already on {@code expectedBranch} and nothing here applies
     */
    private ChangeOutcome checkWrongBranch(
            Path repoPath, String expectedBranch, String baselineSha, Set<String> baselineUntrackedFiles) {
        String actualBranch = git.currentBranch(repoPath);
        if (actualBranch.equals(expectedBranch)) {
            return null;
        }
        String actualSha = git.currentHeadSha(repoPath);

        // Discards only this checkout's own uncommitted state on the wrong branch -- never a commit
        // already on it, which is left in place, untouched and available for a human to inspect. The
        // untracked-file baseline was captured before the attempt started, on whatever branch was checked
        // out then -- untracked files are a working-tree property, not a per-branch one, so it applies
        // here unchanged regardless of which branch the attempt ends up leaving checked out.
        git.resetHard(repoPath, actualSha);
        removeAttemptCreatedUntrackedFiles(repoPath, baselineUntrackedFiles);
        git.checkout(repoPath, expectedBranch);
        git.resetHard(repoPath, baselineSha);

        return new ChangeOutcome(ChangeDisposition.ROLLED_BACK, null, "", List.of(),
                "The implementation finished on \"" + actualBranch + "\" (at " + actualSha + ") instead "
                        + "of the remediation branch \"" + expectedBranch + "\". Nothing found there is "
                        + "trusted or carried over onto the remediation branch -- this needs a human to "
                        + "look at what actually happened on \"" + actualBranch + "\" directly.", null);
    }

    /**
     * Undoes any commit the implementation made on its own, without losing its content.
     *
     * <p>Claude now has full local git, including {@code commit} -- the implementation prompt asks it
     * to leave the remediation as uncommitted working-tree edits and let this class do the actual
     * commit, but nothing at the tool level enforces that, so it cannot be assumed. If the branch has
     * moved past {@code baselineSha} at all, whatever is there is undone with {@code git reset --mixed},
     * which keeps the change as an ordinary <em>unstaged</em> difference against the baseline --
     * deliberately not {@code --soft}, which would leave it staged and trip
     * {@link RemediationDiffPolicy#checkBeforeStaging}'s own check for exactly that (a stage the
     * orchestrator did not itself perform is normally the signature of Claude having run {@code git add},
     * which still is not allowed). Unstaged is what makes every check and decision below see, and act
     * on, exactly the same change whether Claude left it uncommitted as asked or committed it anyway: a
     * self-made commit can shortcut how this class gets to its answer, never what that answer is based
     * on.
     */
    private void reconcileAnySelfMadeCommits(Path repoPath, String baselineSha) {
        if (!git.currentHeadSha(repoPath).equals(baselineSha)) {
            git.resetMixed(repoPath, baselineSha);
        }
    }

    private static String rollbackReason(
            boolean workCompleted, boolean policyAllowed, String refusalReason, List<String> violations) {
        if (!workCompleted) {
            return "The implementation did not complete the remediation, so the partial changes it had "
                    + "already made were undone.";
        }
        if (!policyAllowed) {
            return "The change was rejected by the diff policy: " + String.join("; ", violations) + ".";
        }
        return "The change was not kept: " + refusalReason;
    }
}
