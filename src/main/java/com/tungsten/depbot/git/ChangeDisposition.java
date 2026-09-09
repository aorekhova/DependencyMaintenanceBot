package com.tungsten.depbot.git;

/** What the orchestrator did with whatever an implementation left in the working tree. */
public enum ChangeDisposition {

    /**
     * The change was staged and committed on the remediation branch. "Pending validation" is not
     * hedging: nothing has compiled or tested the result, so this means "kept for review", never
     * "correct".
     */
    COMMITTED_PENDING_VALIDATION,

    /**
     * The working tree was returned to the branch tip it started from. Every outcome that is not a
     * clean, policy-passing completion ends here -- a failed or timed-out call, an unreadable report, a
     * stop on contradicted evidence, or a diff the policy refused.
     */
    ROLLED_BACK,

    /**
     * Nothing was modified at all, so there was nothing to commit or roll back. Distinct from
     * {@link #ROLLED_BACK} because no work was undone: it is what a deliberate, well-reasoned "this
     * needs no change here" looks like on disk.
     */
    NO_CHANGES
}
