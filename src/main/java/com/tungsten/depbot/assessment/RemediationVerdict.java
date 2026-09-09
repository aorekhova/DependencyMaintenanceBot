package com.tungsten.depbot.assessment;

/**
 * What the bot decided to do with an assessment. Produced only by {@link ImpactScorePolicy} -- never
 * supplied by Claude, so an assessment cannot authorise its own execution.
 */
public enum RemediationVerdict {

    /** An implementation call may run: a branch is created and Claude carries out its own plan. */
    AUTOMATIC_ALLOWED,

    /**
     * No implementation call runs. The analysis judged this remediation group unsafe to trust to
     * automation, but not blocked outright -- a read-only Human Review Engineer call writes up a report
     * (what is vulnerable, why, what would fix it, how to validate) for a person to act on instead.
     * Nothing about the group is changed by the bot. Reached from
     * {@link AutomationSafety#HUMAN_REVIEW_REQUIRED}, independently of how large the change is.
     */
    HUMAN_REVIEW_REQUIRED,

    /**
     * No automatic change is made, and the same read-only Human Review Engineer call runs as for
     * {@link #HUMAN_REVIEW_REQUIRED}. Reached from {@link AutomationSafety#AUTOMATION_BLOCKED}, from an
     * inconclusive finding, and from any finding or whole batch that could not be read or validated at
     * all -- the policy fails closed, so an unusable answer is treated exactly like one judged unsafe to
     * automate. The distinction a report should draw is in what a reviewer should expect: this verdict
     * means no safe plan could be established or trusted at all, where {@link #HUMAN_REVIEW_REQUIRED}
     * means a safe, reviewable plan existed but was simply not authorised to run unattended.
     */
    MANUAL_REMEDIATION_REQUIRED,

    /**
     * Nothing needs doing: the finding does not apply to this repository. Distinct from
     * {@link #MANUAL_REMEDIATION_REQUIRED} because there is nothing for a human to pick up either --
     * the answer is that the dependency is not here.
     */
    NO_ACTION_REQUIRED
}
