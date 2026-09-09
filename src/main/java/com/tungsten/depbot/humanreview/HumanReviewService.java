package com.tungsten.depbot.humanreview;

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
import java.util.Objects;

/**
 * The Human Review Engineer: one short, strictly read-only call that turns whatever the analysis
 * already established (or, failing that, the raw Mend finding) into a report for a person -- never a
 * remediation.
 *
 * <p>Much simpler than {@code RemediationImplementationService}: no validation gate, no commit, no
 * full build, and no possibility of a {@code GitCommandException} -- this class never touches git at
 * all. Its own fail-safe mirrors the other two roles': if the primary call runs out of turns or time, a
 * short, tool-free finalization call writes up a best-effort report from whatever was already gathered.
 */
public final class HumanReviewService {

    /** The validated report. Present only when one was actually produced. */
    public static final String REPORT_FILE = "human-review-report.json";

    /**
     * The same report, deterministically rendered as Markdown by the orchestrator once it is written --
     * see {@code VulnerabilityRemediationService}'s own writing of this file, never produced here. Named
     * as a sibling of {@link #REPORT_FILE} so both are found together.
     */
    public static final String REPORT_MARKDOWN_FILE = "human-review-report.md";

    /** The invocation record. Always present, whatever happened. */
    public static final String ATTEMPT_FILE = "human-review-attempt.json";

    /** Where the finalization call's own artifacts are written -- never the primary call's own directory. */
    static final String FINALIZATION_SUBDIRECTORY = "finalization";

    private static final String MAX_TURNS_SUBTYPE = "error_max_turns";
    private static final String ATTEMPT_DIRECTORY = "attempt-1";

    private final ClaudeInvoker invoker;
    private final ClaudeConfig config;
    private final RemediationRunService runService;
    private final HumanReviewPromptRenderer promptRenderer;
    private final HumanReviewFinalizationPromptRenderer finalizationPromptRenderer;
    private final HumanReviewReportParser parser;
    private final ClaudeResultExtractor resultExtractor;
    private final HumanReviewJsonRenderer jsonRenderer;

    public HumanReviewService(
            ClaudeInvoker invoker,
            ClaudeConfig config,
            RemediationRunService runService,
            HumanReviewPromptRenderer promptRenderer) {
        this(invoker, config, runService, promptRenderer, new HumanReviewFinalizationPromptRenderer(),
                new HumanReviewReportParser(), new ClaudeResultExtractor(), new HumanReviewJsonRenderer());
    }

    HumanReviewService(
            ClaudeInvoker invoker,
            ClaudeConfig config,
            RemediationRunService runService,
            HumanReviewPromptRenderer promptRenderer,
            HumanReviewFinalizationPromptRenderer finalizationPromptRenderer,
            HumanReviewReportParser parser,
            ClaudeResultExtractor resultExtractor,
            HumanReviewJsonRenderer jsonRenderer) {
        this.invoker = Objects.requireNonNull(invoker, "invoker");
        this.config = Objects.requireNonNull(config, "config");
        this.runService = Objects.requireNonNull(runService, "runService");
        this.promptRenderer = Objects.requireNonNull(promptRenderer, "promptRenderer");
        this.finalizationPromptRenderer =
                Objects.requireNonNull(finalizationPromptRenderer, "finalizationPromptRenderer");
        this.parser = Objects.requireNonNull(parser, "parser");
        this.resultExtractor = Objects.requireNonNull(resultExtractor, "resultExtractor");
        this.jsonRenderer = Objects.requireNonNull(jsonRenderer, "jsonRenderer");
    }

    /** Where this unit's human review artifacts belong, without writing anything. */
    public Path humanReviewDirectoryFor(String runId, String unitId) {
        return runService.unitDirectoryFor(runId, unitId)
                .resolve(ClaudePhase.HUMAN_REVIEW.directoryName())
                .resolve(ATTEMPT_DIRECTORY);
    }

    public HumanReviewOutcome review(HumanReviewContext context) {
        Objects.requireNonNull(context, "context");

        Path directory = humanReviewDirectoryFor(context.runId(), context.unitId());
        ClaudeRunRequest request = ClaudeRunRequest.of(
                ClaudePhase.HUMAN_REVIEW, context.workspace(), promptRenderer.render(context), directory, config);

        ClaudeRunOutcome claudeOutcome = invoker.run(request);

        if (ranOutOfInvestigationRoom(claudeOutcome, request)) {
            return finalize(context, claudeOutcome, request, directory);
        }

        if (!claudeOutcome.completedCleanly()) {
            return failClosed(context, claudeOutcome, directory, claudeOutcome.failureReason(), false);
        }

        ClaudeResult result;
        try {
            result = resultExtractor.extractFrom(request.stdoutFile());
        } catch (ClaudeOutputException e) {
            return failClosed(context, claudeOutcome, directory, e.getMessage(), false);
        }

        if (result.isError()) {
            return failClosed(context, claudeOutcome, directory,
                    "Claude reported an error result (subtype " + result.subtype() + "), so its answer is "
                            + "not a completed human review.", false);
        }

        return parseAndRecord(context, claudeOutcome, directory, result.text(), false);
    }

    private boolean ranOutOfInvestigationRoom(ClaudeRunOutcome claudeOutcome, ClaudeRunRequest request) {
        if (claudeOutcome.timedOut()) {
            return true;
        }
        return MAX_TURNS_SUBTYPE.equals(resultExtractor.readSubtypeIfPresent(request.stdoutFile()));
    }

    private HumanReviewOutcome finalize(
            HumanReviewContext context,
            ClaudeRunOutcome primaryOutcome,
            ClaudeRunRequest primaryRequest,
            Path directory) {

        String sessionId = resultExtractor.readSessionIdIfPresent(primaryRequest.stdoutFile());
        String finalizationPrompt = finalizationPromptRenderer.render(context, sessionId != null);
        Path finalizationDirectory = directory.resolve(FINALIZATION_SUBDIRECTORY);

        ClaudeRunRequest finalizationRequest = ClaudeRunRequest.ofHumanReviewFinalization(
                context.workspace(), finalizationPrompt, finalizationDirectory, config, sessionId);

        ClaudeRunOutcome finalizationOutcome = invoker.run(finalizationRequest);

        if (!finalizationOutcome.completedCleanly()) {
            return failClosed(context, finalizationOutcome, directory,
                    describeFinalizationFailure(primaryOutcome, finalizationOutcome.failureReason()), true);
        }

        ClaudeResult result;
        try {
            result = resultExtractor.extractFrom(finalizationRequest.stdoutFile());
        } catch (ClaudeOutputException e) {
            return failClosed(context, finalizationOutcome, directory,
                    describeFinalizationFailure(primaryOutcome, e.getMessage()), true);
        }

        if (result.isError()) {
            return failClosed(context, finalizationOutcome, directory,
                    describeFinalizationFailure(primaryOutcome,
                            "it reported an error result itself (subtype " + result.subtype() + ")"), true);
        }

        return parseAndRecord(context, finalizationOutcome, directory, result.text(), true);
    }

    private static String describePrimaryRanOutOfRoom(ClaudeRunOutcome primaryOutcome) {
        return primaryOutcome.timedOut()
                ? "it did not finish within its timeout"
                : "it ran out of turns (Claude reported subtype \"" + MAX_TURNS_SUBTYPE + "\")";
    }

    private static String describeFinalizationFailure(ClaudeRunOutcome primaryOutcome, String finalizationReason) {
        return "The human review ran out of turns or time -- " + describePrimaryRanOutOfRoom(primaryOutcome)
                + " -- and the report-only finalization attempt also did not produce a usable report: "
                + finalizationReason;
    }

    private HumanReviewOutcome parseAndRecord(
            HumanReviewContext context,
            ClaudeRunOutcome claudeOutcome,
            Path directory,
            String answerText,
            boolean finalizationUsed) {

        HumanReviewReport report;
        try {
            report = parser.parse(answerText);
        } catch (HumanReviewParseException e) {
            String reason = finalizationUsed
                    ? "The report-only finalization attempt answered, but its document did not validate: "
                            + e.getMessage()
                    : e.getMessage();
            return failClosed(context, claudeOutcome, directory, reason, finalizationUsed);
        }

        // Bot-owned facts, stamped on after parsing -- never part of what Claude was asked to fill in,
        // and never derived from anything Claude wrote. Mirrors RemediationReport.commitSha, filled in
        // only once the bot itself knows it.
        report = new HumanReviewReport(
                report.schemaVersion(), report.coordinates(), report.vulnerabilitySummary(),
                report.whyVulnerable(), report.dependencyOrigin(), report.recommendedChange(),
                report.relatedDependenciesToConsider(), report.validationApproach(), report.openQuestions(),
                report.risks(), null, context.integrationJenkinsValidation(),
                context.cumulativeJenkinsValidation());

        runService.writeAttemptFile(directory.resolve(REPORT_FILE), jsonRenderer.render(report));
        writeAttempt(context, claudeOutcome, directory, true, finalizationUsed, null);

        return new HumanReviewOutcome(
                context.runId(), context.unitId(), context.coordinates(), report, claudeOutcome, directory, null);
    }

    private HumanReviewOutcome failClosed(
            HumanReviewContext context,
            ClaudeRunOutcome claudeOutcome,
            Path directory,
            String safeReason,
            boolean finalizationUsed) {

        String reason = (safeReason == null || safeReason.isBlank())
                ? "the human review did not produce a usable report"
                : safeReason;

        writeAttempt(context, claudeOutcome, directory, false, finalizationUsed, reason);

        return new HumanReviewOutcome(
                context.runId(), context.unitId(), context.coordinates(), null, claudeOutcome, directory, reason);
    }

    private void writeAttempt(
            HumanReviewContext context,
            ClaudeRunOutcome claudeOutcome,
            Path directory,
            boolean reportUsable,
            boolean finalizationUsed,
            String failureReason) {

        HumanReviewAttempt attempt = new HumanReviewAttempt(
                context.runId(),
                context.unitId(),
                ClaudePhase.HUMAN_REVIEW.name(),
                config.model(),
                context.coordinates(),
                context.reviewedRef(),
                context.reviewedSha(),
                claudeOutcome.command(),
                claudeOutcome.startedAt(),
                claudeOutcome.finishedAt(),
                claudeOutcome.exitCode(),
                claudeOutcome.timedOut(),
                reportUsable,
                finalizationUsed,
                failureReason);

        runService.writeAttemptFile(directory.resolve(ATTEMPT_FILE), jsonRenderer.renderAttempt(attempt));
    }
}
