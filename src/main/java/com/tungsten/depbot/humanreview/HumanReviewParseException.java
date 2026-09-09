package com.tungsten.depbot.humanreview;

/** Claude's Human Review answer could not be read as a valid {@link HumanReviewReport}. */
public class HumanReviewParseException extends RuntimeException {

    public HumanReviewParseException(String message) {
        super(message);
    }

    public HumanReviewParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
