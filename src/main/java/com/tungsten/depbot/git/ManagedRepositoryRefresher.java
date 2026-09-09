package com.tungsten.depbot.git;

import java.nio.file.Path;
import java.util.Objects;

/**
 * Brings the managed checkout's current branch to the verified tip of its own remote counterpart,
 * once, before the Vulnerability Analysis Engineer ever investigates it.
 *
 * <p>{@link RemoteRefsRefresher} only updates {@code origin/*} remote-tracking refs -- it never moves
 * the local, checked-out branch forward. Without this step, the branch Claude investigates could be an
 * arbitrary number of commits behind what is actually on GitLab, and the analysis would be reasoning
 * about a stale snapshot without any way to know it.
 *
 * <p>Fails closed when the run started detached: there is no branch name to resolve a remote counterpart
 * for, so nothing is refreshed and nothing is investigated. This is the orchestrator's own step, run once
 * for the whole batch -- Claude is never given {@code git fetch}/{@code git reset} at the tool level.
 *
 * <p>Also fails closed on unsafe divergence: {@code git reset --hard} is only ever performed when the
 * managed checkout's own local commit is a genuine ancestor of the verified remote tip -- a pure
 * fast-forward, where nothing is reachable only from the local branch. A local commit that is not an
 * ancestor of the remote (an unpushed local commit, a stray commit left by a previous failed run, or any
 * other divergence) is never silently discarded by this reset; the run stops here and asks a human to
 * look, exactly the same way a plain {@code git pull --ff-only} would refuse.
 */
public final class ManagedRepositoryRefresher {

    private final GitCommandRunner git;
    private final SourceRefVerifier sourceRefVerifier;

    public ManagedRepositoryRefresher(GitCommandRunner git, SourceRefVerifier sourceRefVerifier) {
        this.git = Objects.requireNonNull(git, "git");
        this.sourceRefVerifier = Objects.requireNonNull(sourceRefVerifier, "sourceRefVerifier");
    }

    public RepositoryRefreshOutcome refresh(Path repoPath, OriginalState original) {
        Objects.requireNonNull(repoPath, "repoPath");
        Objects.requireNonNull(original, "original");

        if (original.detached()) {
            return RepositoryRefreshOutcome.failed(null,
                    "The checkout was detached at the start of this run, so there is no branch to refresh "
                            + "against its remote counterpart.");
        }

        String sourceRef = RemoteRefsRefresher.DEFAULT_REMOTE + "/" + original.branchName();
        SourceRefVerification verification = sourceRefVerifier.verify(repoPath, sourceRef, null);
        if (!verification.verified()) {
            return RepositoryRefreshOutcome.failed(sourceRef,
                    "Could not verify " + sourceRef + ": " + verification.failureReason());
        }

        if (!git.isClean(repoPath)) {
            return RepositoryRefreshOutcome.failed(sourceRef,
                    "The working tree is not clean, so it cannot be safely reset to " + sourceRef + ".");
        }

        String localSha = original.headSha();
        if (!localSha.equals(verification.resolvedSha())) {
            boolean fastForward;
            try {
                fastForward = git.isAncestor(repoPath, localSha, verification.resolvedSha());
            } catch (GitCommandException e) {
                return RepositoryRefreshOutcome.failed(sourceRef,
                        "Could not determine whether " + localSha + " is an ancestor of "
                                + verification.resolvedSha() + ": " + e.getMessage());
            }
            if (!fastForward) {
                return RepositoryRefreshOutcome.failed(sourceRef,
                        "The managed checkout's local commit (" + localSha + ") has diverged from "
                                + sourceRef + " (" + verification.resolvedSha() + ") -- it is not a fast-forward, "
                                + "so resetting to it would discard commits reachable only from the local branch. "
                                + "Resolve this by hand (inspect and, if safe, reconcile the managed checkout at "
                                + repoPath + ") before running remediate again; it will not be done automatically.");
            }
        }

        try {
            git.resetHard(repoPath, verification.resolvedSha());
        } catch (GitCommandException e) {
            return RepositoryRefreshOutcome.failed(sourceRef,
                    "Could not reset the checkout to " + verification.resolvedSha() + ": " + e.getMessage());
        }

        if (!git.isClean(repoPath)) {
            return RepositoryRefreshOutcome.failed(sourceRef,
                    "The working tree was not clean after resetting to " + verification.resolvedSha() + ".");
        }

        return RepositoryRefreshOutcome.refreshed(sourceRef, verification.resolvedSha());
    }
}
