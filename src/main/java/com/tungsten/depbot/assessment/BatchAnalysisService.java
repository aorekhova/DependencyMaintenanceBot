package com.tungsten.depbot.assessment;

import com.tungsten.depbot.claude.ClaudeConfig;
import com.tungsten.depbot.claude.ClaudeInvoker;
import com.tungsten.depbot.claude.ClaudeOutputException;
import com.tungsten.depbot.claude.ClaudePhase;
import com.tungsten.depbot.claude.ClaudeResult;
import com.tungsten.depbot.claude.ClaudeResultExtractor;
import com.tungsten.depbot.claude.ClaudeRunOutcome;
import com.tungsten.depbot.claude.ClaudeRunRequest;
import com.tungsten.depbot.run.RemediationRunService;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The Vulnerability Analysis Engineer: one whole-batch call that investigates every Mend finding in a
 * run at once, freely, and decides both each finding's own conclusion and which findings must be
 * remediated together as a {@link AnalysisRemediationGroup}.
 *
 * <p>This replaces the old one-call-per-finding {@code DeveloperAssessmentService}. The business logic
 * is the same shape -- compose the problem statement, run the one read-only call, read back what came
 * out, validate it, record all of it -- just scaled to a whole batch. What a group's automation-safety
 * decision means for whether it gets implemented is decided afterwards, per group, by
 * {@link ImpactScorePolicy} and the orchestrator -- this class only produces and validates the analysis
 * document itself.
 *
 * <p><strong>Running out of turns or time is not, by itself, a failure that stops the run -- and it is
 * never allowed to throw away real progress.</strong> When the first attempt ends that way, a second
 * attempt runs: the <em>same</em> investigative tools as the first ({@link
 * ClaudeRunRequest#ofAssessmentSecondAttempt}, never the old tool-free write-up), a smaller turn/time
 * budget, and -- whenever the first attempt's session can be resumed -- everything it had already
 * established still in context. When it produces a valid, coverage-complete {@link BatchAnalysis},
 * routing proceeds exactly as if the first attempt had succeeded on its own. There is never a third
 * attempt.
 *
 * <p><strong>An attempt answering a finding is not, by itself, proof the finding was actually
 * examined.</strong> {@link AnalysisCoverageValidator} checks the second attempt's own document for
 * exactly that failure mode (every finding, or some of them, answered {@code INCONCLUSIVE} with no real
 * evidence of examination) before this class ever calls the result usable. When it finds one, the result
 * is {@link BatchAnalysisStatus#INCOMPLETE}. The first attempt's own output is never run through this
 * check: Vulnerability Analysis stays a free investigation, not a checklist Java re-grades.
 *
 * <p><strong>If the second attempt also runs out of turns or time, nothing is discarded.</strong> Whatever
 * either attempt actually established -- session content when resumed, or raw answer text when not -- is
 * preserved as a {@link PartialAnalysisState} and the result is {@link BatchAnalysisStatus#PARTIAL}: a
 * distinct outcome from both a completed analysis and a total failure, routed by
 * {@code VulnerabilityRemediationService} to a constrained, per-finding Remediation Engineer fallback (or
 * Human Review, when even that cannot determine a direction) rather than stopping the whole run.
 *
 * <p>Only when neither attempt produces a usable answer for a reason other than running out of turns or
 * time does {@link BatchAnalysisOutcome#hasAnalysis()} come back {@code false} with
 * {@link BatchAnalysisStatus#FAILED} -- at which point every finding in the batch is routed to Human
 * Review Engineer rather than discarded (see {@code VulnerabilityRemediationService}).
 *
 * <p><strong>A call that itself completed substantively, but whose final document could not be parsed or
 * validated, is not treated the same as a genuine failure.</strong> Missing a required field, an invalid
 * enum value, or a malformed JSON wrapper are output-contract defects, not evidence the investigation
 * itself was deficient -- discarding a whole real investigation (and fanning every one of its findings
 * out to individual Human Review calls) over a formatting defect is exactly the failure mode this guards
 * against. Exactly one bounded, tool-free schema-repair call is made in that case (see
 * {@link #runSchemaRepairAttempt}) -- the same Vulnerability Analysis Engineer, resuming its own session
 * whenever possible, told plainly what is structurally wrong and asked to correct the document's shape
 * alone, never to re-investigate or change a substantive conclusion. If the repaired document is valid,
 * routing proceeds exactly as if that attempt had produced it directly, with no coverage gate (the same
 * trust the first attempt's own output already gets). If it is still unusable, this is a genuine failure
 * after all, and the existing {@link BatchAnalysisStatus#FAILED} path applies -- there is never a second
 * repair attempt. This is deliberately narrow: a genuine timeout/{@code error_max_turns} (handled by the
 * second-attempt scheme above), a substantive validation problem ({@code ANALYSIS_VALIDATION_FAILED} --
 * e.g. an inconsistent group/finding cross-reference), and a self-reported error or crash
 * ({@code NON_ZERO_EXIT}) are never eligible for schema repair; only {@code MISSING_ANALYSIS} (no JSON
 * document found at all) and {@code MALFORMED_ANALYSIS} (a document was found but could not be bound) are.
 *
 * <p>Every path writes {@code analysis-attempt.json}. The validated {@code analysis.json} is written
 * only when there is a valid, coverage-complete document to write, so its presence is itself the signal
 * that the run succeeded. An {@code INCOMPLETE} result's own (untrusted) document is preserved
 * separately as {@code analysis-incomplete.json}; a {@code PARTIAL} result's combined progress is
 * preserved as {@code partial-analysis-state.json} -- neither ever under {@link #ANALYSIS_FILE}'s name,
 * which means "this was validated and is safe to route."
 */
public final class BatchAnalysisService {

    /** The validated analysis. Present only when a coverage-complete one was actually produced. */
    public static final String ANALYSIS_FILE = "analysis.json";

    /**
     * The second attempt's own document, preserved for a human to inspect, when it exists but
     * {@link AnalysisCoverageValidator} refused to trust it. Never read back by anything in this
     * application; distinct from {@link #ANALYSIS_FILE} specifically so its presence never implies the
     * document was validated as safe to route.
     */
    public static final String INCOMPLETE_ANALYSIS_FILE = "analysis-incomplete.json";

    /**
     * What survived from both attempts when neither produced a coverage-complete document -- see
     * {@link PartialAnalysisState}. Present only for {@link BatchAnalysisStatus#PARTIAL}.
     */
    public static final String PARTIAL_ANALYSIS_STATE_FILE = "partial-analysis-state.json";

    /** The invocation record. Always present, whatever happened. */
    public static final String ATTEMPT_FILE = "analysis-attempt.json";

    /**
     * Where the second attempt's own {@code prompt.md}/{@code stdout.json} are written -- a subdirectory
     * of the analysis directory, never the analysis directory itself, so the second attempt never
     * overwrites the first attempt's own artifacts.
     */
    static final String SECOND_ATTEMPT_SUBDIRECTORY = "attempt-2";

    /**
     * Where the one bounded schema-repair attempt's own {@code prompt.md}/{@code stdout.json} are
     * written -- its own subdirectory, distinct from both {@link #ATTEMPT_DIRECTORY} and
     * {@link #SECOND_ATTEMPT_SUBDIRECTORY}, so it never overwrites either attempt's own evidence,
     * whichever one it followed.
     */
    static final String SCHEMA_REPAIR_SUBDIRECTORY = "schema-repair";

    /**
     * The subtype Claude Code reports when a call ends because its turn budget ran out. Matched
     * exactly, and only against this one value.
     */
    private static final String MAX_TURNS_SUBTYPE = "error_max_turns";

    private static final String ANALYSIS_SUBDIRECTORY = "analysis";
    private static final String ATTEMPT_DIRECTORY = "attempt-1";

    private final ClaudeInvoker invoker;
    private final ClaudeConfig config;
    private final RemediationRunService runService;
    private final BatchAnalysisPromptRenderer promptRenderer;
    private final BatchAnalysisSecondAttemptPromptRenderer secondAttemptPromptRenderer;
    private final BatchAnalysisSchemaRepairPromptRenderer schemaRepairPromptRenderer;
    private final BatchAnalysisParser parser;
    private final ClaudeResultExtractor resultExtractor;
    private final AnalysisJsonRenderer jsonRenderer;

    public BatchAnalysisService(
            ClaudeInvoker invoker,
            ClaudeConfig config,
            RemediationRunService runService,
            BatchAnalysisPromptRenderer promptRenderer) {
        this(invoker, config, runService, promptRenderer, new BatchAnalysisSecondAttemptPromptRenderer(),
                new BatchAnalysisSchemaRepairPromptRenderer(), new BatchAnalysisParser(),
                new ClaudeResultExtractor(), new AnalysisJsonRenderer());
    }

    BatchAnalysisService(
            ClaudeInvoker invoker,
            ClaudeConfig config,
            RemediationRunService runService,
            BatchAnalysisPromptRenderer promptRenderer,
            BatchAnalysisSecondAttemptPromptRenderer secondAttemptPromptRenderer,
            BatchAnalysisSchemaRepairPromptRenderer schemaRepairPromptRenderer,
            BatchAnalysisParser parser,
            ClaudeResultExtractor resultExtractor,
            AnalysisJsonRenderer jsonRenderer) {
        this.invoker = Objects.requireNonNull(invoker, "invoker");
        this.config = Objects.requireNonNull(config, "config");
        this.runService = Objects.requireNonNull(runService, "runService");
        this.promptRenderer = Objects.requireNonNull(promptRenderer, "promptRenderer");
        this.secondAttemptPromptRenderer =
                Objects.requireNonNull(secondAttemptPromptRenderer, "secondAttemptPromptRenderer");
        this.schemaRepairPromptRenderer =
                Objects.requireNonNull(schemaRepairPromptRenderer, "schemaRepairPromptRenderer");
        this.parser = Objects.requireNonNull(parser, "parser");
        this.resultExtractor = Objects.requireNonNull(resultExtractor, "resultExtractor");
        this.jsonRenderer = Objects.requireNonNull(jsonRenderer, "jsonRenderer");
    }

    /** Where this run's analysis artifacts belong, without writing anything. */
    public Path analysisDirectoryFor(String runId) {
        return runService.runDirectoryFor(runId).resolve(ANALYSIS_SUBDIRECTORY).resolve(ATTEMPT_DIRECTORY);
    }

    public BatchAnalysisOutcome analyze(AnalysisContext context) {
        Objects.requireNonNull(context, "context");

        Path analysisDirectory = analysisDirectoryFor(context.runId());
        ClaudeRunRequest request = ClaudeRunRequest.of(
                ClaudePhase.ASSESSMENT,
                context.workspace(),
                promptRenderer.render(context),
                analysisDirectory,
                config);

        ClaudeRunOutcome attempt1Outcome = invoker.run(request);
        AttemptClassification attempt1 = classifyAttempt(attempt1Outcome, request.stdoutFile());

        // The first attempt's own free investigation is trusted as-is -- no coverage gate applies to it.
        if (attempt1.analysis() != null) {
            return recordComplete(context, attempt1.analysis(), attempt1Outcome, analysisDirectory,
                    attempt1.invocation(), null);
        }

        if (isSchemaRepairEligible(attempt1)) {
            // The call itself completed substantively -- this is an output-contract defect, not evidence
            // the investigation was deficient. One bounded, tool-free repair call, never a second.
            return runSchemaRepairAttempt(
                    context, request, attempt1, attempt1.invocation(), null, analysisDirectory);
        }

        if (!attempt1.ranOutOfRoom()) {
            // Something is actually broken -- crashed outright, self-reported an error, or answered with
            // something that would not validate, none of which is "ran out of room." No second attempt:
            // there is nothing a continuation would add.
            return recordFailed(context, attempt1Outcome, analysisDirectory, attempt1.failureReason(),
                    attempt1.invocation(), null);
        }

        return runSecondAttempt(context, request, attempt1, analysisDirectory);
    }

    /**
     * The second, budget-halved attempt -- run only after the first ran out of turns or time. Keeps the
     * same investigative tools as the first (never the old tool-free write-up) and resumes the first
     * attempt's own session whenever one was captured, so real progress is continued, not re-derived.
     * There is never a third attempt: whatever this one produces (or fails to) is final.
     */
    private BatchAnalysisOutcome runSecondAttempt(
            AnalysisContext context,
            ClaudeRunRequest firstRequest,
            AttemptClassification attempt1,
            Path analysisDirectory) {

        String sessionId = resultExtractor.readSessionIdIfPresent(firstRequest.stdoutFile());
        boolean resuming = sessionId != null;
        String secondPrompt = secondAttemptPromptRenderer.render(context, resuming, attempt1.rawText());
        Path secondAttemptDirectory = analysisDirectory.resolve(SECOND_ATTEMPT_SUBDIRECTORY);

        ClaudeRunRequest secondRequest = ClaudeRunRequest.ofAssessmentSecondAttempt(
                context.workspace(), secondPrompt, secondAttemptDirectory, config, sessionId);

        ClaudeRunOutcome attempt2Outcome = invoker.run(secondRequest);
        AttemptClassification attempt2 = classifyAttempt(attempt2Outcome, secondRequest.stdoutFile());

        if (attempt2.analysis() != null) {
            Optional<String> incompleteReason = AnalysisCoverageValidator.incompletenessReason(attempt2.analysis());
            if (incompleteReason.isPresent()) {
                return recordIncomplete(context, attempt2.analysis(), attempt2Outcome, analysisDirectory,
                        attempt1.invocation(), attempt2.invocation(), incompleteReason.get());
            }
            return recordComplete(context, attempt2.analysis(), attempt2Outcome, analysisDirectory,
                    attempt1.invocation(), attempt2.invocation());
        }

        if (attempt2.ranOutOfRoom()) {
            // Both attempts ran out of room -- this is the one case that must never become INCOMPLETE
            // (a whole-batch dead stop) or FAILED (a full per-finding Human Review fan-out): real partial
            // progress from one or both attempts exists and must reach the orchestrator's fallback.
            return recordPartial(context, attempt2Outcome, analysisDirectory, attempt1, attempt2);
        }

        if (isSchemaRepairEligible(attempt2)) {
            // The continuation attempt itself completed substantively -- same reasoning as attempt1's
            // own schema-repair path, just following the second call instead of the first.
            return runSchemaRepairAttempt(context, secondRequest, attempt2, attempt1.invocation(),
                    attempt2.invocation(), analysisDirectory);
        }

        // The second attempt failed for a reason other than running out of room -- crashed outright, or
        // answered with something that would not validate. Nothing further to attempt.
        String reason = "The first Vulnerability Analysis attempt ran out of turns or time (" + attempt1.failureReason()
                + "), and the second attempt also did not produce a usable analysis: " + attempt2.failureReason();
        return recordFailed(context, attempt2Outcome, analysisDirectory, reason,
                attempt1.invocation(), attempt2.invocation());
    }

    /** Whether {@code attempt} is eligible for the one bounded schema-repair call: the call itself
     *  completed (never a timeout or {@code error_max_turns}), but its document either could not be
     *  found at all or was found and could not be bound -- an output-contract defect, never a
     *  substantive validation problem ({@code ANALYSIS_VALIDATION_FAILED}) or a self-reported
     *  error/crash ({@code NON_ZERO_EXIT}), neither of which a repair call could do anything about. */
    private static boolean isSchemaRepairEligible(AttemptClassification attempt) {
        AnalysisInvocationOutcomeReason reason = attempt.invocation().outcomeReason();
        return reason == AnalysisInvocationOutcomeReason.MISSING_ANALYSIS
                || reason == AnalysisInvocationOutcomeReason.MALFORMED_ANALYSIS;
    }

    /**
     * The one bounded, tool-free schema-repair call: resumes {@code mostRecentAttempt}'s own session
     * whenever it can, tells it exactly what is structurally wrong, and asks it to correct the
     * document's shape alone -- never to re-investigate or change a substantive conclusion, and never a
     * second attempt at this repair regardless of what it produces. A repaired document is trusted
     * exactly like a first attempt's own output (no coverage gate: the investigation itself already
     * completed, this call only fixed how it was written down); an unusable one falls back to the
     * existing failure path with all three invocations' own evidence preserved.
     */
    private BatchAnalysisOutcome runSchemaRepairAttempt(
            AnalysisContext context,
            ClaudeRunRequest mostRecentRequest,
            AttemptClassification mostRecentAttempt,
            AnalysisInvocationRecord attempt1Invocation,
            AnalysisInvocationRecord attempt2Invocation,
            Path analysisDirectory) {

        String sessionId = resultExtractor.readSessionIdIfPresent(mostRecentRequest.stdoutFile());
        boolean resuming = sessionId != null;
        String repairPrompt = schemaRepairPromptRenderer.render(
                resuming, mostRecentAttempt.rawText(), mostRecentAttempt.failureReason());
        Path repairDirectory = analysisDirectory.resolve(SCHEMA_REPAIR_SUBDIRECTORY);

        ClaudeRunRequest repairRequest = ClaudeRunRequest.ofAssessmentFinalization(
                context.workspace(), repairPrompt, repairDirectory, config, sessionId);

        ClaudeRunOutcome repairOutcome = invoker.run(repairRequest);
        AttemptClassification repaired = classifyAttempt(repairOutcome, repairRequest.stdoutFile());

        if (repaired.analysis() != null) {
            return recordComplete(context, repaired.analysis(), repairOutcome, analysisDirectory,
                    attempt1Invocation, attempt2Invocation, repaired.invocation());
        }

        String reason = "the batch analysis document could not be read (" + mostRecentAttempt.failureReason()
                + "), and the one bounded schema-repair attempt also did not produce a usable document: "
                + repaired.failureReason();
        return recordFailed(context, repairOutcome, analysisDirectory, reason,
                attempt1Invocation, attempt2Invocation, repaired.invocation());
    }

    /**
     * Everything one attempt (first or second) actually produced, classified once so both call sites
     * share exactly the same logic: {@code analysis} is non-null only for a coverage-untested, structurally
     * valid document; {@code rawText} is Claude's own last message whenever the process produced one, kept
     * so a run that could not resume its session can still be handed a lead rather than nothing;
     * {@code ranOutOfRoom} is true for {@code PROCESS_TIMEOUT}/{@code MAX_TURNS_EXCEEDED} specifically,
     * the one condition that ever justifies a further attempt or the partial-analysis fallback.
     */
    private record AttemptClassification(
            BatchAnalysis analysis,
            String failureReason,
            String rawText,
            AnalysisInvocationRecord invocation,
            boolean ranOutOfRoom) {
    }

    private AttemptClassification classifyAttempt(ClaudeRunOutcome outcome, Path stdoutFile) {
        String subtype = resultExtractor.readSubtypeIfPresent(stdoutFile);
        boolean maxTurnsExceeded = MAX_TURNS_SUBTYPE.equals(subtype);

        BatchAnalysis analysis = null;
        String failureReason = null;
        String rawText = null;
        AnalysisInvocationOutcomeReason reason;

        if (outcome.timedOut()) {
            failureReason = "it did not finish within its timeout";
            reason = AnalysisInvocationOutcomeReason.PROCESS_TIMEOUT;
            rawText = captureRawResultText(stdoutFile);
        } else if (maxTurnsExceeded) {
            failureReason = "it ran out of turns (Claude reported subtype \"" + MAX_TURNS_SUBTYPE + "\")";
            reason = AnalysisInvocationOutcomeReason.MAX_TURNS_EXCEEDED;
            rawText = captureRawResultText(stdoutFile);
        } else if (!outcome.completedCleanly()) {
            failureReason = outcome.failureReason();
            reason = AnalysisInvocationOutcomeReason.NON_ZERO_EXIT;
        } else {
            try {
                ClaudeResult result = resultExtractor.extractFrom(stdoutFile);
                rawText = result.text();
                if (result.isError()) {
                    failureReason = "Claude reported an error result (subtype " + result.subtype()
                            + "), so its answer is not a completed analysis.";
                    reason = AnalysisInvocationOutcomeReason.NON_ZERO_EXIT;
                } else {
                    analysis = parser.parse(result.text());
                    reason = AnalysisInvocationOutcomeReason.COMPLETED;
                }
            } catch (ClaudeOutputException e) {
                failureReason = e.getMessage();
                reason = AnalysisInvocationOutcomeReason.MISSING_ANALYSIS;
            } catch (AssessmentParseException e) {
                failureReason = e.getMessage();
                reason = reasonFor(e.kind());
            }
        }

        AnalysisInvocationRecord invocation = new AnalysisInvocationRecord(
                outcome.command(), outcome.startedAt(), outcome.finishedAt(), outcome.exitCode(),
                outcome.timedOut(), maxTurnsExceeded, subtype, reason, analysis != null);

        boolean ranOutOfRoom = outcome.timedOut() || maxTurnsExceeded;
        return new AttemptClassification(analysis, failureReason, rawText, invocation, ranOutOfRoom);
    }

    /** Best-effort only: {@code null} for a genuinely killed process (a wall-clock timeout leaves no output). */
    private String captureRawResultText(Path stdoutFile) {
        try {
            return resultExtractor.extractFrom(stdoutFile).text();
        } catch (ClaudeOutputException e) {
            return null;
        }
    }

    private BatchAnalysisOutcome recordComplete(
            AnalysisContext context,
            BatchAnalysis analysis,
            ClaudeRunOutcome effectiveOutcome,
            Path analysisDirectory,
            AnalysisInvocationRecord attempt1Invocation,
            AnalysisInvocationRecord attempt2Invocation) {
        return recordComplete(context, analysis, effectiveOutcome, analysisDirectory,
                attempt1Invocation, attempt2Invocation, null);
    }

    private BatchAnalysisOutcome recordComplete(
            AnalysisContext context,
            BatchAnalysis analysis,
            ClaudeRunOutcome effectiveOutcome,
            Path analysisDirectory,
            AnalysisInvocationRecord attempt1Invocation,
            AnalysisInvocationRecord attempt2Invocation,
            AnalysisInvocationRecord repairInvocation) {

        runService.writeAttemptFile(analysisDirectory.resolve(ANALYSIS_FILE), jsonRenderer.render(analysis));
        writeAttempt(context, analysisDirectory, true, attempt2Invocation != null, repairInvocation != null,
                BatchAnalysisStatus.COMPLETE, null, attempt1Invocation, attempt2Invocation, repairInvocation);

        return new BatchAnalysisOutcome(context.runId(), analysis, BatchAnalysisStatus.COMPLETE, null, null,
                effectiveOutcome, analysisDirectory);
    }

    private BatchAnalysisOutcome recordFailed(
            AnalysisContext context,
            ClaudeRunOutcome effectiveOutcome,
            Path analysisDirectory,
            String safeReason,
            AnalysisInvocationRecord attempt1Invocation,
            AnalysisInvocationRecord attempt2Invocation) {
        return recordFailed(context, effectiveOutcome, analysisDirectory, safeReason,
                attempt1Invocation, attempt2Invocation, null);
    }

    private BatchAnalysisOutcome recordFailed(
            AnalysisContext context,
            ClaudeRunOutcome effectiveOutcome,
            Path analysisDirectory,
            String safeReason,
            AnalysisInvocationRecord attempt1Invocation,
            AnalysisInvocationRecord attempt2Invocation,
            AnalysisInvocationRecord repairInvocation) {

        String reason = (safeReason == null || safeReason.isBlank())
                ? "the batch analysis did not produce a usable answer"
                : safeReason;

        writeAttempt(context, analysisDirectory, false, attempt2Invocation != null, repairInvocation != null,
                BatchAnalysisStatus.FAILED, reason, attempt1Invocation, attempt2Invocation, repairInvocation);

        return new BatchAnalysisOutcome(context.runId(), null, BatchAnalysisStatus.FAILED, null, null,
                effectiveOutcome, analysisDirectory);
    }

    private BatchAnalysisOutcome recordIncomplete(
            AnalysisContext context,
            BatchAnalysis untrustedAnalysis,
            ClaudeRunOutcome effectiveOutcome,
            Path analysisDirectory,
            AnalysisInvocationRecord attempt1Invocation,
            AnalysisInvocationRecord attempt2Invocation,
            String incompleteReason) {

        // Preserved for a human to inspect what the second attempt actually produced -- but never under
        // ANALYSIS_FILE's name, which means "this was validated and is safe to route."
        runService.writeAttemptFile(
                analysisDirectory.resolve(INCOMPLETE_ANALYSIS_FILE), jsonRenderer.render(untrustedAnalysis));
        writeAttempt(context, analysisDirectory, false, true, false,
                BatchAnalysisStatus.INCOMPLETE, incompleteReason, attempt1Invocation, attempt2Invocation, null);

        return new BatchAnalysisOutcome(context.runId(), null, BatchAnalysisStatus.INCOMPLETE, incompleteReason,
                null, effectiveOutcome, analysisDirectory);
    }

    /**
     * Both attempts ran out of turns or time. Nothing is discarded: whatever either attempt actually
     * established is preserved as {@link PartialAnalysisState} and this run is handed to the
     * orchestrator's constrained, per-finding Remediation Engineer fallback -- never stopped outright,
     * and never masked as ten fabricated {@code INCONCLUSIVE} findings.
     */
    private BatchAnalysisOutcome recordPartial(
            AnalysisContext context,
            ClaudeRunOutcome effectiveOutcome,
            Path analysisDirectory,
            AttemptClassification attempt1,
            AttemptClassification attempt2) {

        PartialAnalysisState partialState = new PartialAnalysisState(
                new AnalysisAttemptSummary(attempt1.invocation(), attempt1.rawText()),
                new AnalysisAttemptSummary(attempt2.invocation(), attempt2.rawText()));

        runService.writeAttemptFile(analysisDirectory.resolve(PARTIAL_ANALYSIS_STATE_FILE),
                jsonRenderer.renderPartialAnalysisState(partialState));

        String reason = "both Vulnerability Analysis attempts ran out of turns or time -- the first ("
                + attempt1.failureReason() + ") and the second (" + attempt2.failureReason() + "); proceeding "
                + "per finding with whatever partial progress survived, rather than discarding it";
        writeAttempt(context, analysisDirectory, false, true, false, BatchAnalysisStatus.PARTIAL, reason,
                attempt1.invocation(), attempt2.invocation(), null);

        return new BatchAnalysisOutcome(context.runId(), null, BatchAnalysisStatus.PARTIAL, null, partialState,
                effectiveOutcome, analysisDirectory);
    }

    private void writeAttempt(
            AnalysisContext context,
            Path analysisDirectory,
            boolean analysisUsable,
            boolean secondAttemptUsed,
            boolean schemaRepairUsed,
            BatchAnalysisStatus status,
            String failureReason,
            AnalysisInvocationRecord attempt1Invocation,
            AnalysisInvocationRecord attempt2Invocation,
            AnalysisInvocationRecord repairInvocation) {

        List<String> coordinates = context.workItems().stream().map(VulnerabilityWorkItem::coordinates).toList();

        BatchAnalysisAttempt attempt = new BatchAnalysisAttempt(
                context.runId(),
                ClaudePhase.ASSESSMENT.name(),
                config.model(),
                coordinates,
                attempt1Invocation.command(),
                attempt1Invocation.startedAt(),
                attempt1Invocation.finishedAt(),
                attempt1Invocation.exitCode(),
                attempt1Invocation.timedOut(),
                analysisUsable,
                secondAttemptUsed,
                schemaRepairUsed,
                status,
                failureReason,
                attempt1Invocation,
                attempt2Invocation,
                repairInvocation);

        runService.writeAttemptFile(analysisDirectory.resolve(ATTEMPT_FILE), jsonRenderer.renderAttempt(attempt));
    }

    private static AnalysisInvocationOutcomeReason reasonFor(AssessmentParseException.Kind kind) {
        return switch (kind) {
            case MISSING_ANALYSIS -> AnalysisInvocationOutcomeReason.MISSING_ANALYSIS;
            case MALFORMED_ANALYSIS -> AnalysisInvocationOutcomeReason.MALFORMED_ANALYSIS;
            case ANALYSIS_VALIDATION_FAILED -> AnalysisInvocationOutcomeReason.ANALYSIS_VALIDATION_FAILED;
        };
    }
}
