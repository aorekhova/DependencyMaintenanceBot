package com.tungsten.depbot.publication;

/** See {@link RemoteIdentityVerifier}. */
public record VerificationResult(boolean verified, String reason) {

    public static VerificationResult success() {
        return new VerificationResult(true, null);
    }

    public static VerificationResult mismatch(String reason) {
        return new VerificationResult(false, reason);
    }
}
