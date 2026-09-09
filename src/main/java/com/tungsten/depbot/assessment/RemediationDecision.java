package com.tungsten.depbot.assessment;

import java.util.Objects;

/**
 * The bot's decision about one assessment, with the reason it reached it.
 *
 * <p>The reason is carried alongside the verdict rather than left to be reconstructed, because
 * {@link RemediationVerdict#MANUAL_REMEDIATION_REQUIRED} is reached for genuinely different causes --
 * a score of 9 or 10, an inconclusive investigation, an unreadable answer -- and an operator looking
 * at a skipped library needs to know which.
 */
public record RemediationDecision(RemediationVerdict verdict, String reason) {

    public RemediationDecision {
        Objects.requireNonNull(verdict, "verdict");
        Objects.requireNonNull(reason, "reason");
        if (reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be blank");
        }
    }

    /**
     * Whether the Remediation Engineer runs. True only for {@link RemediationVerdict#AUTOMATIC_ALLOWED}.
     * Every other verdict -- including {@link RemediationVerdict#HUMAN_REVIEW_REQUIRED}, which no longer
     * runs an implementation call at all -- routes instead to the read-only Human Review Engineer or,
     * for {@link RemediationVerdict#NO_ACTION_REQUIRED}, to nothing further.
     */
    public boolean implementationAllowed() {
        return verdict == RemediationVerdict.AUTOMATIC_ALLOWED;
    }
}
