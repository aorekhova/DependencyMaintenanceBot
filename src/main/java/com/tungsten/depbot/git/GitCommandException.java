package com.tungsten.depbot.git;

/**
 * A {@code git} invocation failed or could not be started.
 *
 * <p>The message includes the command and git's own output. That is safe to show: git never
 * receives a credential as a command-line argument here (authentication is whatever the
 * repository's own remote configuration already uses), so its output carries no secret this
 * application has any special obligation to redact.
 */
public class GitCommandException extends RuntimeException {

    public GitCommandException(String message) {
        super(message);
    }

    public GitCommandException(String message, Throwable cause) {
        super(message, cause);
    }
}
