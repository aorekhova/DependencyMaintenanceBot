package com.tungsten.depbot.jenkins;

/**
 * A Jenkins-facing operation (requesting a crumb, triggering a build, resolving a queue item) could not
 * be completed. Never carries the API token in its message -- only what Jenkins itself returned or a
 * description of the local failure.
 */
public final class JenkinsValidationException extends RuntimeException {

    public JenkinsValidationException(String message) {
        super(message);
    }

    public JenkinsValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
