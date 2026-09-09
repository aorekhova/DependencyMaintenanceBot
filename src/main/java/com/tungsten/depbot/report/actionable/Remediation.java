package com.tungsten.depbot.report.actionable;

import java.util.List;

/**
 * What this report recommends doing about a finding.
 *
 * <p>{@code topFix} is Mend's single preferred remediation and may legitimately be {@code null}.
 * {@code allFixes} is never {@code null} — an absent list is reported as empty, so consumers can
 * iterate without a null check — and is always an immutable copy.
 *
 * <p>Null <em>elements</em> are rejected rather than silently filtered. Removing them is the
 * mapper's responsibility, so a null arriving here indicates a defect upstream and should surface
 * immediately rather than being quietly absorbed by the model.
 */
public record Remediation(
        RecommendedFix topFix,
        List<RecommendedFix> allFixes) {

    private static final Remediation EMPTY = new Remediation(null, List.of());

    public Remediation {
        allFixes = allFixes == null ? List.of() : List.copyOf(allFixes);
    }

    /** A remediation carrying no recommendation at all. */
    public static Remediation empty() {
        return EMPTY;
    }

    public boolean hasTopFix() {
        return topFix != null;
    }

    public boolean hasAnyFix() {
        return topFix != null || !allFixes.isEmpty();
    }
}
