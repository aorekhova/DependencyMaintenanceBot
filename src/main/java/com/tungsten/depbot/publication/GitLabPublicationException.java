package com.tungsten.depbot.publication;

/**
 * A GitLab-facing operation (finding or creating a Merge Request or Issue, posting a commit comment)
 * could not be completed. Never carries the private token in its message -- only what GitLab itself
 * returned or a description of the local failure.
 */
public final class GitLabPublicationException extends RuntimeException {

    public GitLabPublicationException(String message) {
        super(message);
    }

    public GitLabPublicationException(String message, Throwable cause) {
        super(message, cause);
    }
}
