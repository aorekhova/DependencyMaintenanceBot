package com.tungsten.depbot.claude;

/**
 * What one Claude Code process did.
 *
 * <p>{@code exitCode} is {@code null} when the process never produced one -- it timed out and was
 * killed, or it could not be started at all. {@code startFailure} is set only in that last case,
 * and carries a message safe to show (a path and a reason, never file content).
 */
public record ClaudeInvocation(Integer exitCode, boolean timedOut, String startFailure) {

    public static ClaudeInvocation completed(int exitCode) {
        return new ClaudeInvocation(exitCode, false, null);
    }

    /** Named to avoid clashing with the {@code timedOut()} record accessor. */
    public static ClaudeInvocation killedAfterTimeout() {
        return new ClaudeInvocation(null, true, null);
    }

    public static ClaudeInvocation failedToStart(String message) {
        return new ClaudeInvocation(null, false, message);
    }

    public boolean started() {
        return startFailure == null;
    }

    public boolean succeeded() {
        return exitCode != null && exitCode == 0;
    }
}
