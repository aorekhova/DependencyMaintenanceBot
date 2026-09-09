package com.tungsten.depbot.claude;

/**
 * What Claude actually answered, lifted out of its {@code --output-format json} document.
 *
 * <p>{@code text} is the {@code result} field: the final message, which for the assessment phase is
 * where the assessment document itself is found. {@code isError} is Claude Code's own
 * {@code is_error} flag -- distinct from the process exit code, since a run can exit 0 having ended
 * in an error state (a turn limit reached, for instance), and a caller that only checked the exit
 * code would treat that as a usable answer.
 */
public record ClaudeResult(boolean isError, String subtype, String text) {

    public ClaudeResult {
        text = text == null ? "" : text;
    }

    /** True when Claude reported no error and actually said something. */
    public boolean usable() {
        return !isError && !text.isBlank();
    }
}
