package com.tungsten.depbot.humanreview;

import java.util.List;

/**
 * The record of one Human Review Engineer call, written as {@code human-review-attempt.json} next to
 * the captured prompt, stdout and stderr -- written whether or not the call produced a usable report.
 */
public record HumanReviewAttempt(
        String runId,
        String unitId,
        String phase,
        String model,
        String coordinates,
        String reviewedRef,
        String reviewedSha,
        List<String> command,
        String startedAt,
        String finishedAt,
        Integer exitCode,
        boolean timedOut,
        boolean reportUsable,
        boolean finalizationUsed,
        String failureReason) {

    public HumanReviewAttempt {
        command = command == null ? List.of() : List.copyOf(command);
    }
}
