package com.tungsten.depbot.remediation;

/**
 * The actionable report {@code plan-remediation} reads as input could not be found or understood.
 *
 * <p>The message must never include the file's content: even though the source report is already
 * redacted, it is still report data, and this exception's message is printed straight to the
 * console.
 */
public class RemediationSourceException extends RuntimeException {

    public RemediationSourceException(String safeMessage) {
        super(safeMessage);
    }

    public RemediationSourceException(String safeMessage, Throwable cause) {
        super(safeMessage, cause);
    }
}
