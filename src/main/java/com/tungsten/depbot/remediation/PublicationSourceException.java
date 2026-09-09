package com.tungsten.depbot.remediation;

/**
 * A standalone {@code publish} could not find or understand a run's persisted {@code cohorts.json}/
 * {@code remediation-summary.json} -- almost always because the named run id does not exist, or never
 * reached the point of writing them.
 *
 * <p>The message must never include file content: even though these files are already redacted, they
 * are still report data, and this exception's message is printed straight to the console.
 */
public class PublicationSourceException extends RuntimeException {

    public PublicationSourceException(String safeMessage) {
        super(safeMessage);
    }

    public PublicationSourceException(String safeMessage, Throwable cause) {
        super(safeMessage, cause);
    }
}
