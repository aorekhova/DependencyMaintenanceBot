package com.tungsten.depbot.remediation;

/**
 * Why an automatic remediation attempt was rejected -- orthogonal to {@link GroupOutcomeState}, which
 * records only what the outcome was. A {@link RejectedGroupOutcome} always carries exactly one of these,
 * independent of whether the surrounding entry is classified {@code AUTOMATIC_REJECTED_WITH_REPORT} or
 * {@code AUTOMATIC_REJECTED_NO_REPORT}.
 */
public enum RejectionStage {

    /** The implementation call never produced a usable report, or never committed at all. */
    IMPLEMENTATION,

    /** Committed, but the local dependency-resolution gate did not pass. */
    DEPENDENCY_VALIDATION,

    /**
     * Committed, and every other accept-gate condition passed, but the resulting commit is not exactly
     * one direct, single-parent descendant of the cohort's current accepted tip (no new commit at all,
     * more than one commit stacked, or a merge commit) -- "one accepted group, one commit" is a hard
     * invariant, not an assumption.
     */
    MALFORMED_COMMIT,

    /** Committed, dependency validation passed, but the full application build failed. */
    FULL_BUILD,

    /** Committed and locally validated, but cumulative Jenkins validation failed. */
    CUMULATIVE_JENKINS,

    /** The resulting diff was refused by policy. */
    POLICY_VIOLATION,

    /**
     * The repository could not be confirmed safely restored to the accepted cumulative tip after this
     * group was rejected -- the one stage where the cohort's loop stops rather than continuing to the
     * next group.
     */
    UNSAFE_REPOSITORY_STATE,

    /**
     * Implementation itself self-reported {@link com.tungsten.depbot.implementation.ImplementationConclusion#STOPPED_PLAN_DEVIATION_REQUIRED},
     * or a Java-owned structural re-check found the actual diff deviated from the Vulnerability Analysis
     * Engineer's own plan -- either signal alone is sufficient.
     */
    PLAN_DEVIATION_REQUIRED
}
