package com.tungsten.depbot.assessment;

import java.util.List;

/**
 * The record of one whole-batch Vulnerability Analysis Engineer run, written as
 * {@code analysis-attempt.json} next to the captured prompt, stdout and stderr.
 *
 * <p>Written whether or not the run produced a usable {@link BatchAnalysis} -- a run that ends up
 * routing every one of its findings to Human Review, or to the partial-analysis fallback, must still say
 * so on disk, with the exact command and the reason.
 *
 * <p>{@code secondAttemptUsed} is true whenever the first attempt ran out of turns or time and a second,
 * full-tools attempt was run to continue the investigation -- whether or not that attempt itself
 * succeeded, and whether or not what it produced actually passed coverage validation.
 * {@code status} is the single, explicit answer to "did this run produce something safe to route" -- see
 * {@link BatchAnalysisStatus}.
 *
 * <p><strong>{@code command}, {@code startedAt}, {@code finishedAt}, {@code exitCode} and
 * {@code timedOut} always describe the first attempt, never the second</strong> -- unlike the equivalent
 * flat fields on {@code com.tungsten.depbot.implementation.ImplementationAttempt}, which still describe
 * whichever call produced the overall result. Overwriting these with the second attempt's own values was
 * exactly the bug this shape fixes: a first attempt that ran for its full budget and hit
 * {@code error_max_turns} must never be indistinguishable, in these fields, from a much shorter second
 * attempt. Each attempt's own, independently classified facts are always available in full through
 * {@code attempt1}/{@code attempt2} (see {@link AnalysisInvocationRecord}); {@code attempt2} is
 * {@code null} unless {@code secondAttemptUsed} is true.
 *
 * <p>{@code schemaRepairUsed}/{@code schemaRepairAttempt} cover a third, distinct kind of follow-up call:
 * the whole-batch analysis itself completed substantively (never a timeout or {@code error_max_turns}),
 * but its final document could not be parsed or validated, and exactly one bounded, tool-free
 * schema-repair call was made to fix the document's shape alone -- never a further investigation, and
 * never conflated with {@code attempt2}, which is a genuine continuation of the investigation itself.
 * {@code schemaRepairAttempt} is {@code null} unless {@code schemaRepairUsed} is true; it may follow
 * either {@code attempt1} (when the primary call itself was malformed) or {@code attempt2} (when the
 * continuation attempt was).
 */
public record BatchAnalysisAttempt(
        String runId,
        String phase,
        String model,
        List<String> coordinates,
        List<String> command,
        String startedAt,
        String finishedAt,
        Integer exitCode,
        boolean timedOut,
        boolean analysisUsable,
        boolean secondAttemptUsed,
        boolean schemaRepairUsed,
        BatchAnalysisStatus status,
        String failureReason,
        AnalysisInvocationRecord attempt1,
        AnalysisInvocationRecord attempt2,
        AnalysisInvocationRecord schemaRepairAttempt) {

    public BatchAnalysisAttempt {
        coordinates = coordinates == null ? List.of() : List.copyOf(coordinates);
        command = command == null ? List.of() : List.copyOf(command);
    }

    /** Backward-compatible shape from before {@code schemaRepairUsed}/{@code schemaRepairAttempt}
     *  existed -- defaults both to {@code false}/{@code null}. Kept so any existing caller keeps
     *  compiling unchanged. */
    public BatchAnalysisAttempt(
            String runId, String phase, String model, List<String> coordinates, List<String> command,
            String startedAt, String finishedAt, Integer exitCode, boolean timedOut,
            boolean analysisUsable, boolean secondAttemptUsed, BatchAnalysisStatus status,
            String failureReason, AnalysisInvocationRecord attempt1, AnalysisInvocationRecord attempt2) {
        this(runId, phase, model, coordinates, command, startedAt, finishedAt, exitCode, timedOut,
                analysisUsable, secondAttemptUsed, false, status, failureReason, attempt1, attempt2, null);
    }
}
