package com.tungsten.depbot.remediation;

import java.util.List;

/**
 * One library's remediation entry: what it is, what fixes it, and every CVE that drove it there.
 *
 * <p>{@code targetVersion} is either a real version string or the literal
 * {@link TargetVersionResolver#MANUAL_ANALYSIS_REQUIRED} sentinel when no single version could be
 * confirmed to close every CVE, <em>or</em> when every version that would have closed them all is
 * at or below {@code currentVersion} -- {@link TargetVersionResolver} never recommends a downgrade,
 * no matter how tempting the smallest confirmed-safe candidate looks. That sentinel is independent
 * of which {@link RemediationPlan} bucket this entry ends up in -- a Critical-severity library can
 * still carry it if its version could not be resolved, and a library in
 * {@link RemediationPlan#manualAnalysisRequired()} (put there because its severity was Other) can
 * still have a perfectly resolved target version.
 *
 * <p>{@code manualAnalysisReason} is {@code null} whenever {@code targetVersion} is a real version.
 * It is also {@code null} for the pre-existing manual-analysis causes (no candidate at all, or
 * conflicting per-CVE recommendations that never overlap) -- those keep their historical behaviour
 * of simply staying in their severity bucket unexplained. It is only ever set for the one cause
 * {@link TargetVersionResolver} can point at plainly: every candidate that would close every CVE
 * exists only at or below the current version, so there is nothing left to recommend automatically.
 */
public record LibraryRemediation(
        String groupId,
        String artifactId,
        String currentVersion,
        String targetVersion,
        String maxSeverity,
        List<String> vulnerabilityIds,
        String manualAnalysisReason) {

    public LibraryRemediation {
        vulnerabilityIds = vulnerabilityIds == null ? List.of() : List.copyOf(vulnerabilityIds);
    }

    public String coordinates() {
        return groupId + ":" + artifactId;
    }
}
