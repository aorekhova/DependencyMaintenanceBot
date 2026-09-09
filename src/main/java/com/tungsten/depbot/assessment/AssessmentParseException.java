package com.tungsten.depbot.assessment;

/**
 * Claude's assessment answer could not be read as a valid assessment document.
 *
 * <p>Covers both shapes of the problem: no assessment JSON could be found in the answer at all, and
 * one was found but does not satisfy what its own conclusion requires.
 *
 * <p>Messages describe what is structurally wrong -- a missing field, an out-of-range score, an
 * unrecognised value -- and never quote the surrounding answer text. That text was produced while
 * working inside a real product repository and is treated the same way this application already
 * treats Mend's response text.
 *
 * <p>Callers are expected to turn this into {@link ImpactScorePolicy#failClosed} rather than let it
 * escape: an unreadable assessment means a human decides, not that the run crashes.
 *
 * <p>{@code kind} lets a caller (see {@code BatchAnalysisService}'s invocation classifier) distinguish
 * "no document was even found" from "a document was found but malformed" from "a document parsed but
 * did not satisfy its own findings/groups' requirements" -- three genuinely different facts that used to
 * collapse into one generic failure reason.
 */
public class AssessmentParseException extends RuntimeException {

    /** Why the answer could not be turned into a usable {@link BatchAnalysis}. */
    public enum Kind {
        MISSING_ANALYSIS,
        MALFORMED_ANALYSIS,
        ANALYSIS_VALIDATION_FAILED
    }

    private final Kind kind;

    /** Defaults to {@link Kind#MALFORMED_ANALYSIS} -- kept for any caller predating {@code kind}. */
    public AssessmentParseException(String message) {
        this(message, Kind.MALFORMED_ANALYSIS);
    }

    /** Defaults to {@link Kind#MALFORMED_ANALYSIS} -- kept for any caller predating {@code kind}. */
    public AssessmentParseException(String message, Throwable cause) {
        this(message, Kind.MALFORMED_ANALYSIS, cause);
    }

    public AssessmentParseException(String message, Kind kind) {
        super(message);
        this.kind = kind;
    }

    public AssessmentParseException(String message, Kind kind, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }
}
