package com.tungsten.depbot.implementation;

/**
 * Why one Claude invocation (primary or finalization) ended without a usable, committed report --
 * kept as a flat enum so a genuine process timeout and Claude Code's own {@code error_max_turns} subtype
 * can never be conflated: they are two disjoint values here, never the same field meaning two things.
 */
public enum InvocationOutcomeReason {

    /** The call produced a usable report. */
    COMPLETED,

    /** The call was killed for exceeding its wall-clock timeout -- never called a "max turns" outcome. */
    PROCESS_TIMEOUT,

    /** Claude Code itself reported {@code error_max_turns} -- never called a "timeout" outcome. */
    MAX_TURNS_EXCEEDED,

    /** The call exited with a non-zero code for a reason other than a timeout or max-turns. */
    NON_ZERO_EXIT,

    /** The call completed, but its answer contained no complete JSON report at all. */
    MISSING_REPORT,

    /** A JSON report was found, but it could not be parsed/bound. */
    MALFORMED_REPORT,

    /** The report parsed, but did not satisfy what its own conclusion requires. */
    REPORT_VALIDATION_FAILED
}
