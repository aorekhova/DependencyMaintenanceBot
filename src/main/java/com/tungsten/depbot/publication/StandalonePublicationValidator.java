package com.tungsten.depbot.publication;

import java.nio.file.Path;
import java.util.Optional;

/**
 * Confirms that a tree {@link GitLabPublicationService} itself fabricated for standalone, per-group
 * publication -- one that was never independently validated as remediation ran, only ever cumulatively
 * alongside other groups in its cohort -- genuinely still passes the same gates before it may be published.
 *
 * <p>A clean {@code git cherry-pick} only proves the diff applied without a textual conflict; it proves
 * nothing about whether the resulting tree, considered on its own, still resolves its dependencies,
 * builds, and passes Jenkins the way the cohort's cumulative validation did. This interface exists so
 * {@link GitLabPublicationService} itself never has to know how that is actually checked -- only that it
 * must be, for exactly this one case (a non-first commit of a multi-group cohort).
 *
 * <p>{@link #unavailable()} is the safe, fail-closed default for any wiring that has no Maven/Jenkins
 * context to check with (e.g. the standalone {@code publish} command) -- it never silently trusts an
 * unvalidated tree; it simply reports that standalone publication of this specific group is not possible
 * from this invocation. A wiring that does have that context (the immediate post-{@code remediate}
 * publication, which already built the same gates for remediation itself) supplies a real implementation.
 */
public interface StandalonePublicationValidator {

    /**
     * @param isolatedTip the tip of the freshly (re)computed, disposable local branch already checked out
     *                     at {@code repoPath} -- the tree to validate
     * @return empty on success; the specific, human-readable failure reason otherwise. Never throws.
     */
    Optional<String> revalidate(
            String runId, String unitId, Path repoPath, String verifiedSourceSha, String isolatedTip);

    /** Always fails closed -- never available to silently trust an unvalidated tree. */
    static StandalonePublicationValidator unavailable() {
        return (runId, unitId, repoPath, verifiedSourceSha, isolatedTip) -> Optional.of(
                "standalone re-validation is not available in this invocation (no full-build/Jenkins "
                        + "context configured here) -- retry via a context that has one, e.g. immediately "
                        + "after `remediate`");
    }
}
