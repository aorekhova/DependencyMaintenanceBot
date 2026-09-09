package com.tungsten.depbot.remediation;

import com.tungsten.depbot.implementation.ImplementationOutcome;
import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;

import java.util.Objects;

/**
 * What one implementation attempt produced, once every gate that must pass for it to count as
 * genuinely successful has been checked -- not just {@link ImplementationOutcome}'s own local accept-gate,
 * but the corresponding group/cumulative Jenkins run for this exact candidate too. An attempt is
 * {@link #succeeded()} if and only if the local gate passed, the plan-conformance check passed (see
 * {@code PlanConformanceGate}, not yet wired in as of this stage -- {@link #planConformant()} is always
 * {@code true} here for now), and Jenkins itself succeeded.
 *
 * <p>{@code attemptedPatch} is already-redacted, already-captured (via {@link AttemptedChangeCapture},
 * strictly before any cleanup) evidence of what this attempt actually did -- {@code null} only when the
 * attempt fully succeeded (nothing to reproduce) or genuinely changed nothing at all.
 */
public record ValidatedImplementationOutcome(
        ImplementationOutcome implementation,
        boolean localGatePassed,
        boolean planConformant,
        JenkinsValidationOutcome cumulativeJenkinsValidation,
        boolean succeeded,
        RejectionStage failedStage,
        String attemptedPatch) {

    public ValidatedImplementationOutcome {
        Objects.requireNonNull(implementation, "implementation");
        if (succeeded != (failedStage == null)) {
            throw new IllegalArgumentException(
                    "failedStage must be present if and only if succeeded is false, but succeeded was "
                            + succeeded + " and failedStage was " + failedStage);
        }
    }

    public static ValidatedImplementationOutcome planDeviation(ImplementationOutcome implementation, String attemptedPatch) {
        return new ValidatedImplementationOutcome(
                implementation, false, false, null, false, RejectionStage.PLAN_DEVIATION_REQUIRED, attemptedPatch);
    }

    public static ValidatedImplementationOutcome localGateFailed(
            ImplementationOutcome implementation, RejectionStage failedStage, String attemptedPatch) {
        return new ValidatedImplementationOutcome(
                implementation, false, true, null, false, failedStage, attemptedPatch);
    }

    public static ValidatedImplementationOutcome jenkinsFailed(
            ImplementationOutcome implementation, JenkinsValidationOutcome jenkins, String attemptedPatch) {
        return new ValidatedImplementationOutcome(
                implementation, true, true, jenkins, false, RejectionStage.CUMULATIVE_JENKINS, attemptedPatch);
    }

    public static ValidatedImplementationOutcome success(
            ImplementationOutcome implementation, JenkinsValidationOutcome jenkins) {
        return new ValidatedImplementationOutcome(implementation, true, true, jenkins, true, null, null);
    }
}
