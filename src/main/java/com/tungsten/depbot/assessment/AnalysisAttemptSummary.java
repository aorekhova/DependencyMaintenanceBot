package com.tungsten.depbot.assessment;

import java.util.Objects;

/**
 * One Vulnerability Analysis attempt's execution facts, plus whatever raw text it actually produced --
 * the two things needed to hand real progress to the next attempt, or to a partial-analysis fallback,
 * rather than losing it the moment the attempt itself did not produce a valid {@link BatchAnalysis}.
 *
 * <p>{@code rawResultText} is Claude's own last message, verbatim, whenever the process produced one --
 * present for {@code MAX_TURNS_EXCEEDED} (Claude Code still writes a final document even then) and for a
 * clean-but-unparseable answer, {@code null} for a genuine wall-clock {@code PROCESS_TIMEOUT} (a killed
 * process leaves no output at all) or an outright crash. Never treated as a validated conclusion by
 * anything that reads it -- only as a lead the next attempt, or a human, may choose to check.
 */
public record AnalysisAttemptSummary(AnalysisInvocationRecord invocation, String rawResultText) {

    public AnalysisAttemptSummary {
        Objects.requireNonNull(invocation, "invocation");
    }

    public boolean hasRawResultText() {
        return rawResultText != null && !rawResultText.isBlank();
    }
}
