package com.tungsten.depbot.remediation;

import java.util.List;
import java.util.Optional;

/**
 * Narrows a full {@link RemediationPlan} down to exactly one library, identified by exact
 * {@code groupId:artifactId} coordinates, for a {@code remediate --dependency} pilot run.
 *
 * <p>The matched library stays in whichever of {@link RemediationPlan#critical()},
 * {@link RemediationPlan#high()}, {@link RemediationPlan#medium()} or {@link RemediationPlan#low()}
 * it was already classified into -- narrowing never changes a library's severity, it only empties
 * every bucket except the one real match. Everything downstream (severity-group iteration, branch
 * creation, manifest building) already treats an empty bucket as "nothing to do here", so a plan
 * narrowed this way produces exactly one branch and exactly one {@code RemediationUnit} without any
 * further changes to that logic.
 *
 * <p>A library found only in {@link RemediationPlan#manualAnalysisRequired()} (severity
 * {@code OTHER}) can never become a remediation unit at all, with or without this filter, so it is
 * reported the same way as a library that is not in the plan at all -- both are a pilot request
 * that cannot be honoured.
 */
public final class PilotDependencySelector {

    private PilotDependencySelector() {
    }

    /**
     * @throws DependencyNotFoundException if no library in {@code plan} matches {@code groupId} and
     *                                      {@code artifactId} exactly, or the only match is in
     *                                      {@code manualAnalysisRequired}
     */
    public static RemediationPlan selectOnly(RemediationPlan plan, String groupId, String artifactId) {
        Optional<LibraryRemediation> critical = find(plan.critical(), groupId, artifactId);
        if (critical.isPresent()) {
            return narrowed(plan, critical.get(), true, false, false, false);
        }
        Optional<LibraryRemediation> high = find(plan.high(), groupId, artifactId);
        if (high.isPresent()) {
            return narrowed(plan, high.get(), false, true, false, false);
        }
        Optional<LibraryRemediation> medium = find(plan.medium(), groupId, artifactId);
        if (medium.isPresent()) {
            return narrowed(plan, medium.get(), false, false, true, false);
        }
        Optional<LibraryRemediation> low = find(plan.low(), groupId, artifactId);
        if (low.isPresent()) {
            return narrowed(plan, low.get(), false, false, false, true);
        }

        String coordinates = groupId + ":" + artifactId;
        if (find(plan.manualAnalysisRequired(), groupId, artifactId).isPresent()) {
            throw new DependencyNotFoundException(
                    coordinates + " is in the remediation plan but requires manual analysis "
                            + "(its severity could not be classified), so it cannot be piloted automatically.");
        }
        throw new DependencyNotFoundException(
                "No library matching " + coordinates + " was found in the remediation plan.");
    }

    private static Optional<LibraryRemediation> find(
            List<LibraryRemediation> bucket, String groupId, String artifactId) {
        return bucket.stream()
                .filter(library -> library.groupId().equals(groupId) && library.artifactId().equals(artifactId))
                .findFirst();
    }

    /** Keeps {@code match} in whichever one bucket it actually belongs to, empties the other three. */
    private static RemediationPlan narrowed(
            RemediationPlan plan, LibraryRemediation match,
            boolean inCritical, boolean inHigh, boolean inMedium, boolean inLow) {
        List<LibraryRemediation> only = List.of(match);
        return new RemediationPlan(
                plan.generatedAt(),
                plan.sourceReportGeneratedAt(),
                plan.reportVersion(),
                inCritical ? only : List.of(),
                inHigh ? only : List.of(),
                inMedium ? only : List.of(),
                inLow ? only : List.of(),
                List.of(),
                plan.sourceSnapshotFingerprint());
    }
}
