package com.tungsten.depbot.report.actionable;

/**
 * The severity totals for the whole scan, carried inside the detailed report.
 *
 * <p>These mirror the console summary exactly, so a machine reading the JSON sees the same figures
 * a human read on screen.
 *
 * <p>{@code actionableCount} is the number of findings the report details. The detailed report now
 * includes every severity, so this is always equal to {@link #totalVulnerabilities()} — the field
 * is kept anyway (rather than removed) so the published JSON schema does not change shape for
 * existing consumers.
 */
public record ActionableSummary(
        int totalVulnerabilities,
        int criticalCount,
        int highCount,
        int mediumCount,
        int lowCount,
        int otherCount,
        int actionableCount) {

    /**
     * The five severity buckets added together. A well-formed summary has this equal to
     * {@link #totalVulnerabilities()}; exposing it keeps that invariant cheap to assert.
     */
    public int sumOfBuckets() {
        return criticalCount + highCount + mediumCount + lowCount + otherCount;
    }
}
