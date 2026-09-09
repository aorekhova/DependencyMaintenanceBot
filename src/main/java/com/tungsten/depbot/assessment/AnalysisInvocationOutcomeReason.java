package com.tungsten.depbot.assessment;

/**
 * Why one Claude invocation (primary or finalization) of the Vulnerability Analysis Engineer ended the
 * way it did -- kept as a flat enum so a genuine process timeout and Claude Code's own
 * {@code error_max_turns} subtype can never be conflated: they are two disjoint values here, never the
 * same field meaning two things. Mirrors {@code com.tungsten.depbot.implementation.InvocationOutcomeReason}
 * for the analysis phase.
 */
public enum AnalysisInvocationOutcomeReason {

    /** The call produced a usable, structurally valid batch analysis document. */
    COMPLETED,

    /** The call was killed for exceeding its wall-clock timeout -- never called a "max turns" outcome. */
    PROCESS_TIMEOUT,

    /** Claude Code itself reported {@code error_max_turns} -- never called a "timeout" outcome. */
    MAX_TURNS_EXCEEDED,

    /** The call exited with a non-zero code for a reason other than a timeout or max-turns. */
    NON_ZERO_EXIT,

    /** The call completed, but its answer contained no complete JSON analysis document at all. */
    MISSING_ANALYSIS,

    /** A JSON document was found, but it could not be parsed/bound. */
    MALFORMED_ANALYSIS,

    /** The document parsed, but did not satisfy what {@link BatchAnalysisParser} requires of it. */
    ANALYSIS_VALIDATION_FAILED
}
