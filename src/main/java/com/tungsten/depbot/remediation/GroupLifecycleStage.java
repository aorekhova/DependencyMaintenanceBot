package com.tungsten.depbot.remediation;

/**
 * The last stage transition a group's {@link GroupState} audit trail has actually recorded -- an
 * ever-advancing marker of how far {@code attemptGroup} got, never a resume/recovery instruction: nothing
 * in this codebase reads a group's own {@code group-state.json} back to skip already-done work. It exists
 * so a human (or a future resume feature, without a schema rewrite) can tell exactly where a group's run
 * left off.
 */
public enum GroupLifecycleStage {
    ASSESSED,
    IMPLEMENTATION_ATTEMPT_1,
    /** Dependency validation, the full build, and cumulative Jenkins for attempt 1, resolved either way. */
    VALIDATION_ATTEMPT_1,
    IMPLEMENTATION_ATTEMPT_2,
    /** Dependency validation, the full build, and cumulative Jenkins for attempt 2, resolved either way. */
    VALIDATION_ATTEMPT_2,
    FINAL_OUTCOME_DECIDED,
    PUBLISHED
}
