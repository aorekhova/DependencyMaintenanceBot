package com.tungsten.depbot.remediation;

import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.implementation.ImplementationOutcome;

import java.nio.file.Path;

/**
 * Captures whatever an implementation attempt actually did, as one single {@code git apply}-able patch,
 * strictly before any further cleanup (candidate-branch discard) touches the repository.
 *
 * <p><strong>Primary source: {@code implementation.change().patch()}.</strong>
 * {@code RemediationChangeCommitter} always stages everything (tracked and untracked alike) and captures
 * {@code git diff --cached} <em>before</em> deciding whether to commit or roll back -- so this field is
 * already the complete, correct diff for every outcome that ever touched the working tree, committed or
 * not, and it survives a rollback that has already reset and cleaned the tree by the time this method
 * runs. Re-deriving the diff from live git state after the fact (this class's original approach) is too
 * late for any implementation attempt that stopped without committing -- {@code STOPPED_BLOCKED},
 * {@code STOPPED_ASSESSMENT_CONTRADICTED}, {@code STOPPED_PLAN_DEVIATION_REQUIRED}, or a
 * {@code PlanConformanceGate} rejection -- since {@code RemediationChangeCommitter} has already restored
 * the working tree to baseline in every one of those cases before this method is ever called.
 *
 * <p>The one case {@code change().patch()} is deliberately blank is the "finished on the wrong branch"
 * outcome, where nothing found there is trusted or inspected at all -- there genuinely is nothing to
 * reproduce, so falling back to a live git diff (which would find a clean tree, since that path also
 * resets before returning) is correct here, not a gap.
 *
 * <p>A live-git fallback is kept purely as defense in depth, for any future caller/path that leaves a
 * dirty working tree without populating {@code change().patch()} -- not something the current codebase is
 * known to do, but cheap insurance against silently losing a real, capturable change.
 *
 * <p>Returns the raw, unredacted patch text (or {@code null}) -- the caller is responsible for running it
 * through {@code SecretRedactor} before storing or rendering it anywhere.
 */
public final class AttemptedChangeCapture {

    private AttemptedChangeCapture() {
    }

    public static String capturePatch(
            GitCommandRunner git, Path repository, String acceptedBaseSha, ImplementationOutcome implementation) {
        String capturedPatch = implementation.change().patch();
        if (capturedPatch != null && !capturedPatch.isBlank()) {
            return capturedPatch;
        }
        if (implementation.committed() && implementation.change().commitSha() != null) {
            return git.diffBinary(repository, acceptedBaseSha, implementation.change().commitSha());
        }
        if (!git.isClean(repository)) {
            git.markIntentToAddAll(repository);
            return git.diffWorkingTreeAgainst(repository, acceptedBaseSha);
        }
        return null;
    }
}
