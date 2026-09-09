package com.tungsten.depbot.report.actionable;

/**
 * A remediation this report recommends for a finding.
 *
 * <p>Part of the published report contract, deliberately independent of the Mend integration
 * model: a change to Mend's fix payload must break a mapping function rather than silently
 * reshape the file that downstream automation reads.
 *
 * <p>Every field is optional. A fix carrying only a {@code type} is still reported rather than
 * discarded, and nothing here is ever inferred — {@code fixResolution} in particular is reproduced
 * exactly as supplied or left {@code null}.
 */
public record RecommendedFix(
        String vulnerability,
        String type,
        String origin,
        String url,
        String fixResolution,
        String date,
        String message) {
}
