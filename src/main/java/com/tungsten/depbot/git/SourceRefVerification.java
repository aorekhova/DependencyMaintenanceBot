package com.tungsten.depbot.git;

/**
 * The result of checking, through git, a ref an assessment named.
 *
 * <p>{@code resolvedSha} is the only commit anything is allowed to branch from, and it comes from git.
 * {@code claimedSha} is what the assessment said the ref was at. They are kept side by side, and
 * {@code claimMatched} records whether they agreed -- but a disagreement is <em>not</em> a failure:
 * git is authoritative, and the assessment's SHA was never going to be used either way. A mismatch
 * usually just means the ref moved between the assessment reading it and this check, which is exactly
 * why the bot resolves it again rather than taking the model's word.
 */
public record SourceRefVerification(
        boolean verified,
        String requestedRef,
        String resolvedRef,
        String resolvedSha,
        String claimedSha,
        boolean claimMatched,
        String failureReason) {

    public static SourceRefVerification verified(
            String requestedRef, String resolvedRef, String resolvedSha, String claimedSha) {
        return new SourceRefVerification(true, requestedRef, resolvedRef, resolvedSha, claimedSha,
                resolvedSha.equalsIgnoreCase(claimedSha == null ? "" : claimedSha.strip()), null);
    }

    public static SourceRefVerification rejected(String requestedRef, String claimedSha, String reason) {
        return new SourceRefVerification(false, requestedRef, null, null, claimedSha, false, reason);
    }
}
