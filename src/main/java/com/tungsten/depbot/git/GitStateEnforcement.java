package com.tungsten.depbot.git;

/**
 * What {@link RemediationCheckoutManager#enforceOriginalState} found, and whether it had to act.
 *
 * <p>{@code detail} is set only when {@code wasAsExpected} is {@code false}: the checkout was not where
 * this run left it -- a different branch, a moved commit, an uncommitted or committed change Claude
 * made on its own -- and has been forced back to the expected baseline. Unlike
 * {@link RestoreOutcome}, which never forces anything because it is handing control back to a human,
 * this always succeeds or throws: everything found here can only be a side effect of a tool call this
 * bot itself just made within its own managed run, so there is nothing that needs preserving.
 *
 * <p>"Succeeds" is judged by postcondition -- branch, commit and cleanliness actually match afterward --
 * not by every underlying git command having reported success. {@code detail} says so when a step
 * failed but was tolerated anyway; see {@link RemediationCheckoutManager#enforceOriginalState} for why.
 */
public record GitStateEnforcement(boolean wasAsExpected, String detail) {

    public static GitStateEnforcement clean() {
        return new GitStateEnforcement(true, null);
    }

    public static GitStateEnforcement corrected(String detail) {
        return new GitStateEnforcement(false, detail);
    }
}
