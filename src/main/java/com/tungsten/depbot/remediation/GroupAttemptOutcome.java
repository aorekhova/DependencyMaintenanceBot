package com.tungsten.depbot.remediation;

import java.util.Objects;

/**
 * What one group's whole attempt at automatic remediation produced, across its implementation attempt(s).
 * Attempt 1 always runs -- there is no separate plan-approval gate before it, since the Remediation
 * Engineer carries out the plan the Vulnerability Analysis Engineer already established. {@code
 * attemptsUsed} is 2 only when attempt 1 failed and a repair attempt (the same Remediation Engineer,
 * with the failure's own evidence, forbidden from re-investigating or changing direction) therefore ran.
 * There is no third attempt, ever.
 */
public record GroupAttemptOutcome(
        ValidatedImplementationOutcome finalAttempt,
        int attemptsUsed,
        String applicablePatch) {

    public GroupAttemptOutcome {
        Objects.requireNonNull(finalAttempt, "finalAttempt");
        if (attemptsUsed != 1 && attemptsUsed != 2) {
            throw new IllegalArgumentException("attemptsUsed must be 1 or 2, but was: " + attemptsUsed);
        }
    }

    public static GroupAttemptOutcome accepted(ValidatedImplementationOutcome attempt) {
        return new GroupAttemptOutcome(attempt, 1, null);
    }

    public static GroupAttemptOutcome rejected(ValidatedImplementationOutcome attempt) {
        return new GroupAttemptOutcome(attempt, 1, attempt.attemptedPatch());
    }

    /**
     * The repair attempt ran -- the FINAL outcome either way, accepted or rejected; there is no third
     * attempt, ever.
     */
    public static GroupAttemptOutcome finalAttempt(ValidatedImplementationOutcome attempt2) {
        return new GroupAttemptOutcome(attempt2, 2, attempt2.attemptedPatch());
    }

    public boolean succeeded() {
        return finalAttempt.succeeded();
    }

    /** Which {@link RejectionStage} this group's overall attempt stopped at. */
    public RejectionStage stoppedAtStage() {
        return finalAttempt.failedStage();
    }
}
