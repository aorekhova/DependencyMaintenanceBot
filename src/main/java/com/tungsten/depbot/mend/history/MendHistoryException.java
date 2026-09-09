package com.tungsten.depbot.mend.history;

/**
 * The Mend snapshot history store ({@code reports/mend-history/}) could not be read or written.
 *
 * <p>The message must never include finding content: history entries are already redacted before
 * they are ever written, but this exception's message is printed straight to the console regardless.
 */
public class MendHistoryException extends RuntimeException {

    public MendHistoryException(String safeMessage) {
        super(safeMessage);
    }

    public MendHistoryException(String safeMessage, Throwable cause) {
        super(safeMessage, cause);
    }
}
