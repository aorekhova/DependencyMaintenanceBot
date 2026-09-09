package com.tungsten.depbot.publication;

/**
 * Whether one cohort may be published, and if not, exactly which bot-owned fact was missing or
 * unsuccessful -- never a guess reconstructed from prose. See {@link PublicationEligibility}.
 */
public record EligibilityResult(boolean eligible, String reason) {

    public static EligibilityResult allowed() {
        return new EligibilityResult(true, null);
    }

    public static EligibilityResult ineligible(String reason) {
        return new EligibilityResult(false, reason);
    }
}
