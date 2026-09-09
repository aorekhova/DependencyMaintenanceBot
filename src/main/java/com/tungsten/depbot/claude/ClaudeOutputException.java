package com.tungsten.depbot.claude;

/**
 * Claude Code's output could not be read as the JSON document it was asked for.
 *
 * <p>Messages describe the shape of the problem and never quote the output itself. That output is
 * whatever Claude printed while working inside a real product repository, so it must be treated the
 * same way this application already treats Mend's response text: capable of containing something
 * that should not be echoed to a console or a log.
 */
public class ClaudeOutputException extends RuntimeException {

    public ClaudeOutputException(String message) {
        super(message);
    }

    public ClaudeOutputException(String message, Throwable cause) {
        super(message, cause);
    }
}
