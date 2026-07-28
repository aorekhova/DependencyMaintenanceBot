package com.tungsten.depbot.mend.model;

/**
 * Mend's in-band error envelope, for example
 * {@code {"errorCode":1004,"errorMessage":"Invalid project token"}} returned with HTTP 200.
 *
 * <p>Built only after the parser has validated that {@code errorCode} really is an integer and
 * resolved a usable message. Deserialising into this record directly would be unsafe: a body
 * carrying only {@code errorMessage} would silently produce {@code errorCode = 0}.
 */
public record MendErrorResponse(int errorCode, String errorMessage) {
}
