package com.tungsten.depbot.validation;

/**
 * The result of the local gate run against the working tree before anything is committed.
 *
 * <p><strong>Only {@link #PASSED} permits a commit.</strong> {@link #NOT_RUN} is refused as firmly as
 * {@link #FAILED}, which is a deliberate choice for the last gate before a change is kept: "the build
 * model still resolves and the vulnerable version is gone" is the one thing that can be checked cheaply,
 * and accepting a change without it would mean recording an unverified edit as a successful remediation.
 * Refusing costs nothing that matters -- the diff is preserved either way, so a run refused because the
 * environment could not answer can simply be repeated once it can.
 */
public enum ValidationStatus {

    /** Maven resolved the build model, and the vulnerable version no longer appears. */
    PASSED,

    /**
     * Maven ran and said no: the model would not resolve at all -- a malformed POM, an unresolvable
     * version, a broken BOM import -- or the vulnerable version is still what resolves, meaning the
     * remediation did not take effect however confidently it was reported.
     */
    FAILED,

    /**
     * The gate could not reach a verdict: Maven could not be started, or it outlasted its budget. Not an
     * accusation against the change, but not evidence for it either.
     */
    NOT_RUN;

    public boolean permitsCommit() {
        return this == PASSED;
    }
}
