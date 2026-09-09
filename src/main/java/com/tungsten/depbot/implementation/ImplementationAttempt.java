package com.tungsten.depbot.implementation;

import com.tungsten.depbot.git.ChangeDisposition;
import com.tungsten.depbot.validation.ValidationStatus;

import java.util.List;

/**
 * The record of one implementation call, written as {@code implementation-attempt.json}.
 *
 * <p>Written on every path, including the ones where nothing was kept. A branch that exists with no
 * commit on it has to be explainable, and this is where the explanation lives: the exact command, the
 * branch and the commit it was based on, what the report concluded, what the diff policy said, and what
 * the orchestrator consequently did with the working tree.
 *
 * <p>{@code finalizationUsed} is true whenever the primary call ran out of turns or time and a short,
 * read-only finalization call was attempted to report on what had already changed -- whether or not
 * that attempt itself produced a usable report. {@code command}, {@code exitCode}, {@code timedOut},
 * {@code startedAt} and {@code finishedAt} describe whichever call actually produced this record's
 * outcome: the finalization call when {@code finalizationUsed} is true, the primary call otherwise.
 *
 * <p>{@code dispositionReason} is always a short, clean, bot-composed sentence -- see
 * {@link com.tungsten.depbot.git.ChangeOutcome#reason()}. {@code rollbackDiagnosticDetail} is the one
 * place raw command output belongs, {@code null} for every outcome except a rollback whose own
 * untracked-file cleanup hit a tolerated, non-fatal git error; this file is the internal, diagnostic
 * home for that detail (see {@link com.tungsten.depbot.git.ChangeOutcome#diagnosticDetail()}), never
 * surfaced in {@code dispositionReason} or in any human-facing text derived from this attempt.
 *
 * <p>{@code primaryInvocation}/{@code finalizationInvocation} are each call's own, independently
 * classified execution facts (see {@link InvocationRecord}) -- added so the primary call's own outcome
 * (for example a genuine wall-clock timeout) is never silently overwritten by the finalization call's
 * own, different outcome (for example {@code error_max_turns}) the way the flat {@code command}/
 * {@code exitCode}/{@code timedOut} fields above still are, kept only for whichever call actually
 * produced this record's overall result. {@code finalizationInvocation} is {@code null} unless
 * {@code finalizationUsed} is true.
 */
public record ImplementationAttempt(
        String runId,
        String unitId,
        String phase,
        String model,
        String coordinates,
        String branch,
        String branchBaseSha,
        String verifiedSourceRef,
        List<String> command,
        String startedAt,
        String finishedAt,
        Integer exitCode,
        boolean timedOut,
        boolean reportUsable,
        boolean finalizationUsed,
        ImplementationConclusion conclusion,
        ChangeDisposition disposition,
        String commitSha,
        List<String> policyViolations,
        ValidationStatus validationStatus,
        String validationReason,
        ValidationStatus fullBuildStatus,
        String fullBuildReason,
        String dispositionReason,
        String rollbackDiagnosticDetail,
        String failureReason,
        InvocationRecord primaryInvocation,
        InvocationRecord finalizationInvocation) {

    public ImplementationAttempt {
        command = command == null ? List.of() : List.copyOf(command);
        policyViolations = policyViolations == null ? List.of() : List.copyOf(policyViolations);
    }

    /**
     * The shape this record had before the primary/finalization invocation split -- both new fields
     * default to {@code null}. Kept so any external tool still reading old fields by name is unaffected;
     * production code always uses the full canonical constructor now.
     */
    public ImplementationAttempt(
            String runId, String unitId, String phase, String model, String coordinates, String branch,
            String branchBaseSha, String verifiedSourceRef, List<String> command, String startedAt,
            String finishedAt, Integer exitCode, boolean timedOut, boolean reportUsable,
            boolean finalizationUsed, ImplementationConclusion conclusion, ChangeDisposition disposition,
            String commitSha, List<String> policyViolations, ValidationStatus validationStatus,
            String validationReason, ValidationStatus fullBuildStatus, String fullBuildReason,
            String dispositionReason, String rollbackDiagnosticDetail, String failureReason) {
        this(runId, unitId, phase, model, coordinates, branch, branchBaseSha, verifiedSourceRef, command,
                startedAt, finishedAt, exitCode, timedOut, reportUsable, finalizationUsed, conclusion,
                disposition, commitSha, policyViolations, validationStatus, validationReason,
                fullBuildStatus, fullBuildReason, dispositionReason, rollbackDiagnosticDetail, failureReason,
                null, null);
    }
}
