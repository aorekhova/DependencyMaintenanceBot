package com.tungsten.depbot.claude;

import java.util.List;

/**
 * What one Claude Code invocation itself did -- nothing more. {@code completedCleanly} means the
 * process exited 0 without timing out; it says nothing about whether its changes are safe to keep,
 * which is a separate decision the diff-policy check and commit-or-rollback step make afterward.
 */
public record ClaudeRunOutcome(
        boolean completedCleanly,
        Integer exitCode,
        boolean timedOut,
        String failureReason,
        List<String> command,
        String startedAt,
        String finishedAt) {

    public ClaudeRunOutcome {
        command = command == null ? List.of() : List.copyOf(command);
    }
}
