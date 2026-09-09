package com.tungsten.depbot.remediation;

/**
 * What ultimately became of one group -- never the reason why (see {@link RejectionStage} for that, on
 * the accompanying {@link RejectedGroupOutcome} when one exists). Deliberately distinguishes a rejected
 * automatic attempt whose fallback Human Review report was successfully produced from one where even
 * that could not be produced, so a normal, fully-handled fail-closed path is never indistinguishable
 * from a genuinely unexplained failure.
 */
public enum GroupOutcomeState {

    /** The analysis judged nothing needed to change. */
    NO_ACTION_REQUIRED,

    /** The group's candidate was accepted into the cumulative chain. */
    ACCEPTED,

    /** The analysis itself required a person -- automation was never attempted. */
    HUMAN_REVIEW_REQUIRED,

    /**
     * The whole-batch Vulnerability Analysis this library was part of never produced a coverage-complete,
     * routable result (see {@code BatchAnalysisStatus#INCOMPLETE}) -- neither automation nor Human Review
     * was ever attempted for this library specifically, because the batch it belongs to never reached a
     * point where routing individual findings was safe at all. One incomplete batch analysis produces
     * this state for every one of its findings; it must never be counted as that many independent
     * failures -- see {@link com.tungsten.depbot.remediation.RemediationSummary#analysisIncompleteFindingCount()}.
     */
    ANALYSIS_INCOMPLETE,

    /** An automatic attempt was made and rejected, and a Human Review report was produced for it. */
    AUTOMATIC_REJECTED_WITH_REPORT,

    /** An automatic attempt was made and rejected, and no usable Human Review report could be produced either. */
    AUTOMATIC_REJECTED_NO_REPORT,

    /** A batch-wide or pre-existing condition (for example a restore failure) left this library unsafe. */
    UNSAFE_STATE
}
