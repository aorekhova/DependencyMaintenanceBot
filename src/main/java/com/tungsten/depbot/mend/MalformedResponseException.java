package com.tungsten.depbot.mend;

/**
 * Mend answered with HTTP 200 but the body is neither a usable report nor a well-formed Mend
 * error envelope.
 *
 * <p><strong>Contract:</strong> the reason string passed to this exception is always a literal
 * authored in this codebase. No part of the response body, and no message from an underlying
 * Jackson exception, may ever be concatenated into it — the body could contain sensitive data.
 * The parsing exception is attached as a cause for debugging only, and is never printed.
 */
public class MalformedResponseException extends RuntimeException {

    public MalformedResponseException(String authoredReason) {
        super(authoredReason);
    }

    public MalformedResponseException(String authoredReason, Throwable cause) {
        super(authoredReason, cause);
    }
}
