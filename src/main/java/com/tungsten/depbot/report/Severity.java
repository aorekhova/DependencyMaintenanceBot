package com.tungsten.depbot.report;

import java.util.Locale;

/**
 * A normalised vulnerability severity.
 *
 * <p>This is the single authority for turning Mend's raw severity text into a known value. Two
 * separate consumers depend on it — the console summary counts and the selection of findings for
 * the detailed actionable report — and if each carried its own copy of the rules they could
 * eventually disagree, producing a summary that reports one number of High findings while the
 * detailed report contains another.
 *
 * <p>Declaration order is meaningful: it defines the precedence used when sorting the detailed
 * report, so {@code CRITICAL} sorts before {@code HIGH}.
 */
public enum Severity {

    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,

    /** Anything Mend sent that is missing, blank, or not one of the four known levels. */
    OTHER;

    /**
     * Maps Mend's raw severity text onto a known level. Never throws and never returns
     * {@code null}: unrecognised, blank and {@code null} input all become {@link #OTHER}, so a
     * vulnerability can never be silently dropped just because its severity was unexpected.
     *
     * <p>{@code Locale.ROOT} is required rather than incidental. Under a Turkish default locale
     * {@code "HIGH".toLowerCase()} produces a dotless i, which would fail to match {@code "high"}
     * and quietly reclassify every High finding as {@link #OTHER}.
     */
    public static Severity fromRaw(String raw) {
        if (raw == null) {
            return OTHER;
        }
        return switch (raw.strip().toLowerCase(Locale.ROOT)) {
            case "critical" -> CRITICAL;
            case "high" -> HIGH;
            case "medium" -> MEDIUM;
            case "low" -> LOW;
            default -> OTHER;
        };
    }

    /** True for the severities that belong in the detailed actionable report. */
    public boolean isActionable() {
        return this == CRITICAL || this == HIGH;
    }

    /**
     * An explicit execution-priority rank -- CRITICAL first -- deliberately not the same thing as
     * {@link #ordinal()}. Declaration order happening to match priority order today is a coincidence a
     * future edit (reordering constants, inserting a new one) could silently break with no compiler
     * error; callers that order remediation groups by priority must use this method, never {@code
     * ordinal()}, so that intent stays explicit and immune to reordering.
     */
    public int executionPriorityRank() {
        return switch (this) {
            case CRITICAL -> 0;
            case HIGH -> 1;
            case MEDIUM -> 2;
            case LOW -> 3;
            case OTHER -> 4;
        };
    }
}
