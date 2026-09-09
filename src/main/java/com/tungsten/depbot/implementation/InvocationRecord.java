package com.tungsten.depbot.implementation;

import java.util.List;
import java.util.Objects;

/**
 * One Claude invocation's own execution facts -- distinct from another invocation's, so an
 * {@link ImplementationAttempt} covering both a primary call and a finalization call never has to pick
 * only one set of fields to keep. {@code maxTurnsExceeded} and {@code timedOut} are independent booleans
 * (never inferred from each other), and {@code outcomeReason} is the single, explicit classification a
 * reader should trust over reconstructing one from the booleans.
 */
public record InvocationRecord(
        List<String> command,
        String startedAt,
        String finishedAt,
        Integer exitCode,
        boolean timedOut,
        boolean maxTurnsExceeded,
        String claudeSubtype,
        InvocationOutcomeReason outcomeReason,
        boolean reportUsable) {

    public InvocationRecord {
        Objects.requireNonNull(outcomeReason, "outcomeReason");
        command = command == null ? List.of() : List.copyOf(command);
    }
}
