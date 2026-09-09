package com.tungsten.depbot.remediation;

/** How one group's whole remediation attempt finally concluded, for the {@link GroupState} audit trail. */
public enum GroupFinalOutcomeKind {
    ACCEPTED_ORDINARY,
    ACCEPTED_RISKY,
    HUMAN_REVIEW_IMPLEMENTATION_FAILED,
    HUMAN_REVIEW_PLAN_DEVIATION,
    HUMAN_REVIEW_NO_PLAN_POSSIBLE,
    /** A narrative plan exists, but the analysis-output metadata contract around it is incomplete. */
    HUMAN_REVIEW_ANALYSIS_INCOMPLETE,
    /** The group itself succeeded, but the cohort's shared final-integration Jenkins gate failed -- see §6. */
    BLOCKED_BY_COHORT_INTEGRATION_FAILURE,
    NO_ACTION_REQUIRED
}
