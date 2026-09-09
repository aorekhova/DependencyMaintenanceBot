package com.tungsten.depbot.validation;

/**
 * The last check before a remediation is committed locally.
 *
 * <p>Deliberately narrow. This is not a substitute for building and testing the project -- it cannot tell
 * you the remediation is correct. What it exists to stop is the specific failure the pilot must not
 * produce: a change reported as a successful remediation that is <em>knowably</em> not one, because the
 * build model no longer resolves or because the vulnerable version is still exactly what it was.
 *
 * <p>An interface rather than a class so a caller that has no business running Maven -- a unit test of the
 * surrounding logic -- can supply a verdict directly, and so a fuller gate (compile, tests) can replace it
 * later without touching anything above.
 */
@FunctionalInterface
public interface RemediationValidationGate {

    /** Never throws for an ordinary failure: a gate that cannot answer returns {@link ValidationStatus#NOT_RUN}. */
    ValidationOutcome validate(ValidationRequest request);
}
