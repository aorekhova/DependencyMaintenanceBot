package com.tungsten.depbot.mend;

/**
 * Mend understood the request and rejected it, reporting an error inside an HTTP 200 response.
 *
 * <p>A distinct type so the CLI can map this to its own exit code by exception typing rather
 * than by inspecting a field.
 *
 * <p>The message originates from Mend, not from this application, so it must be treated as
 * untrusted text: it could in principle echo a submitted credential back. It is only ever
 * printed through a reporter seeded with the active secrets.
 */
public class MendApiException extends RuntimeException {

    private final int errorCode;

    public MendApiException(int errorCode, String mendMessage) {
        super(mendMessage);
        this.errorCode = errorCode;
    }

    public int errorCode() {
        return errorCode;
    }
}
