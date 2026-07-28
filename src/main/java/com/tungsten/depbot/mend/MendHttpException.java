package com.tungsten.depbot.mend;

/**
 * The Mend request failed at the transport level: a non-200 status, a refused or unresolvable
 * host, a timeout, or an interrupted call.
 *
 * <p>The message is always text this application authored. The underlying cause is attached for
 * debugging but its own message is never used, for two reasons: on Windows
 * {@code ConnectException.getMessage()} is {@code null} (so concatenating it prints the literal
 * word "null"), and a lower-level message could carry request details.
 */
public class MendHttpException extends RuntimeException {

    public MendHttpException(String safeMessage) {
        super(safeMessage);
    }

    public MendHttpException(String safeMessage, Throwable cause) {
        super(safeMessage, cause);
    }
}
