package com.tungsten.depbot.assessment;

import java.util.List;
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
 *
 * <p><strong>For {@link PlannedChangeType#EXCLUSION_ADDED}, {@code dependencyCoordinates} is always the
 * HOST dependency the exclusion is added to -- the {@code <dependency>} element that gains an
 * {@code <exclusions>} block -- never the coordinate being excluded.</strong> {@code excludedCoordinates}
 * is the (required, non-empty) list of what is actually excluded from that host; a host can gain more
 * than one exclusion at once, so this is a list rather than a single coordinate. This fixes run
 * {@code 20260920-052841-210614}: Claude #1 set {@code dependencyCoordinates} to the host
 * ({@code org.kordamp.json:json-lib-core}) and named the excluded coordinates ({@code junit:junit},
 * {@code org.slf4j:jcl-over-slf4j}) only in the free-form {@code reason} narrative -- but
 * {@code PlanConformanceGate} at the time treated {@code dependencyCoordinates} itself as the excluded
 * coordinate for every {@code EXCLUSION_ADDED} entry, so it went looking for an exclusion of
 * {@code org.kordamp.json:json-lib-core} that could never exist. The contract is now unambiguous and
 * fully structural: nothing downstream ever needs to parse {@code reason}'s prose to know what is
 * actually being excluded from what. {@code excludedCoordinates} is meaningless for every other
 * {@code changeType} and must be left empty there.
 */
public record PlannedDependencyChange(
        String dependencyCoordinates,
        String currentVersion,
        String targetVersion,
        String affectedFile,
        PlannedChangeType changeType,
        String reason,
        List<String> excludedCoordinates) {

    public PlannedDependencyChange {
        if (dependencyCoordinates == null || dependencyCoordinates.isBlank()) {
            throw new IllegalArgumentException("dependencyCoordinates must not be blank");
        }
        if (affectedFile == null || affectedFile.isBlank()) {
            throw new IllegalArgumentException("affectedFile must not be blank");
        }
        Objects.requireNonNull(changeType, "changeType");
        excludedCoordinates = excludedCoordinates == null ? List.of() : List.copyOf(excludedCoordinates);
        if (changeType == PlannedChangeType.EXCLUSION_ADDED) {
            if (excludedCoordinates.isEmpty()) {
                throw new IllegalArgumentException(
                        "excludedCoordinates must not be empty for an EXCLUSION_ADDED entry -- "
                                + "dependencyCoordinates is the host dependency the exclusion is added to, "
                                + "excludedCoordinates names the transitive coordinate(s) actually being "
                                + "excluded from it; naming them only in reason's prose is not enough");
            }
            for (String excluded : excludedCoordinates) {
                if (excluded == null || excluded.isBlank()) {
                    throw new IllegalArgumentException(
                            "excludedCoordinates must not contain a blank entry");
                }
            }
        } else if (!excludedCoordinates.isEmpty()) {
            throw new IllegalArgumentException(
                    "excludedCoordinates is only meaningful for an EXCLUSION_ADDED entry, but changeType "
                            + "is " + changeType);
        }
    }

    /**
     * Backward-compatible shape from before {@code excludedCoordinates} existed -- defaults it to
     * {@code List.of()}. Kept only for the every {@code changeType} other than {@code EXCLUSION_ADDED},
     * which never needed it; an {@code EXCLUSION_ADDED} entry built through this constructor still fails
     * closed (the compact constructor above requires a non-empty {@code excludedCoordinates} for it),
     * forcing every {@code EXCLUSION_ADDED} call site onto the explicit host/excluded contract.
     */
    public PlannedDependencyChange(
            String dependencyCoordinates,
            String currentVersion,
            String targetVersion,
            String affectedFile,
            PlannedChangeType changeType,
            String reason) {
        this(dependencyCoordinates, currentVersion, targetVersion, affectedFile, changeType, reason, List.of());
    }
}
