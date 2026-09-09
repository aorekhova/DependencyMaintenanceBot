package com.tungsten.depbot.report.actionable;

/**
 * Where the affected library was detected.
 *
 * <p>{@code path} is what tells a developer where to look; {@code matchType} describes how the
 * library was identified there. Both are optional and neither is ever invented — a path that Mend
 * did not supply is reported as {@code null}.
 */
public record FindingLocation(
        String path,
        String matchType) {
}
