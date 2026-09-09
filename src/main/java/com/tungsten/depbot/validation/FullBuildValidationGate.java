package com.tungsten.depbot.validation;

/**
 * The second, heavier local gate: a full build of the project on the branch an implementation just
 * committed to.
 *
 * <p>Deliberately not a change to {@link RemediationValidationGate}. That interface is already used as
 * a bare one-argument lambda by every existing caller and test double, and this gate needs a way to
 * report progress during a run that can last tens of minutes -- adding a heartbeat parameter to the
 * existing interface would force every dependency-resolution-gate caller to accommodate a callback it
 * has no use for. Reusing {@link ValidationOutcome}/{@link ValidationStatus}/{@link ValidationRequest}
 * themselves is still correct: this is "gate two", not a new subsystem.
 */
@FunctionalInterface
public interface FullBuildValidationGate {

    /**
     * @param heartbeat called periodically while the build is still running, so a long build does not
     *                  look identical to a hung one. Must never throw; a caller that cannot tell whether
     *                  its own heartbeat is safe should treat it as best-effort and swallow failures.
     */
    ValidationOutcome validate(ValidationRequest request, Runnable heartbeat);
}
