package com.tungsten.depbot.assessment;

import java.util.List;
import java.util.Objects;

/**
 * One Claude invocation's own execution facts -- distinct from another invocation's, so a
 * {@link BatchAnalysisAttempt} covering both a primary call and a finalization call never has to pick
 * only one set of fields to keep. {@code maxTurnsExceeded} and {@code timedOut} are independent booleans
 * (never inferred from each other), and {@code outcomeReason} is the single, explicit classification a
 * reader should trust over reconstructing one from the booleans. Mirrors
 * {@code com.tungsten.depbot.implementation.InvocationRecord} for the analysis phase.
 */
public record AnalysisInvocationRecord(
        List<String> command,
        String startedAt,
        String finishedAt,
        Integer exitCode,
        boolean timedOut,
        boolean maxTurnsExceeded,
        String claudeSubtype,
        AnalysisInvocationOutcomeReason outcomeReason,
        boolean analysisUsable) {

    public AnalysisInvocationRecord {
        Objects.requireNonNull(outcomeReason, "outcomeReason");
        command = command == null ? List.of() : List.copyOf(command);
    }
}
