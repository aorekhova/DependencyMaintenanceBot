package com.tungsten.depbot.implementation;

/**
 * The implementation's answer could not be read as a valid implementation report.
 *
 * <p>Treated exactly like a failed call: whatever is in the working tree is rolled back. An agent that
 * cannot say what it did is not evidence that what it did was correct, and the changes are on a branch
 * nothing has validated.
 *
 * <p>Messages describe what is structurally wrong and never quote the answer text, which was produced
 * while working inside a real product repository.
 *
 * <p>{@code kind} lets a caller (see {@code RemediationImplementationService}'s invocation classifier)
 * distinguish "no report was even found" from "a report was found but malformed" from "a report parsed
 * but did not satisfy its own conclusion's requirements" -- three genuinely different facts that used to
 * collapse into one generic failure reason.
 */
public class ImplementationParseException extends RuntimeException {

    /** Why the answer could not be turned into a usable {@link ImplementationReport}. */
    public enum Kind {
        MISSING_REPORT,
        MALFORMED_REPORT,
        REPORT_VALIDATION_FAILED
    }

    private final Kind kind;

    /** Defaults to {@link Kind#MALFORMED_REPORT} -- kept for any caller predating {@code kind}. */
    public ImplementationParseException(String message) {
        this(message, Kind.MALFORMED_REPORT);
    }

    /** Defaults to {@link Kind#MALFORMED_REPORT} -- kept for any caller predating {@code kind}. */
    public ImplementationParseException(String message, Throwable cause) {
        this(message, Kind.MALFORMED_REPORT, cause);
    }

    public ImplementationParseException(String message, Kind kind) {
        super(message);
        this.kind = kind;
    }

    public ImplementationParseException(String message, Kind kind, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }
}
