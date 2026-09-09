package com.tungsten.depbot.assessment;

import java.util.Objects;

/**
 * One concrete, machine-readable dependency edit the Vulnerability Analysis Engineer intends -- the
 * part of its remediation plan a machine can actually check, alongside the free-form narrative.
 *
 * <p>{@code dependencyCoordinates} and {@code affectedFile} are the two facts a later
 * {@code PlanConformanceGate} checks the real diff against: which coordinate this change is about, and
 * which file it must land in (an allowance, not by itself proof the change was made correctly). Both are
 * required for exactly that reason -- a change with neither is not something anything downstream could
 * ever verify.
 */
public record PlannedDependencyChange(
        String dependencyCoordinates,
        String currentVersion,
        String targetVersion,
        String affectedFile,
        PlannedChangeType changeType,
        String reason) {

    public PlannedDependencyChange {
        if (dependencyCoordinates == null || dependencyCoordinates.isBlank()) {
            throw new IllegalArgumentException("dependencyCoordinates must not be blank");
        }
        if (affectedFile == null || affectedFile.isBlank()) {
            throw new IllegalArgumentException("affectedFile must not be blank");
        }
        Objects.requireNonNull(changeType, "changeType");
    }
}
