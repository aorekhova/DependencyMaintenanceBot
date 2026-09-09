package com.tungsten.depbot.cli;

import com.tungsten.depbot.assessment.VulnerabilityWorkItem;
import com.tungsten.depbot.assessment.VulnerabilityWorkItemFactory;
import com.tungsten.depbot.config.ConfigurationException;
import com.tungsten.depbot.git.DirtyCheckoutException;
import com.tungsten.depbot.git.GitCommandException;
import com.tungsten.depbot.git.RepositoryRefreshOutcome;
import com.tungsten.depbot.publication.GitLabPublicationService;
import com.tungsten.depbot.publication.IssuePublicationStatus;
import com.tungsten.depbot.publication.PublicationIndex;
import com.tungsten.depbot.remediation.CohortsIndex;
import com.tungsten.depbot.remediation.CohortsIndexJsonReader;
import com.tungsten.depbot.remediation.DependencyCoordinates;
import com.tungsten.depbot.remediation.InvalidDependencyFilterException;
import com.tungsten.depbot.remediation.PublicationSourceException;
import com.tungsten.depbot.remediation.RemediationCohort;
import com.tungsten.depbot.remediation.RemediationPlan;
import com.tungsten.depbot.remediation.RemediationPlanCommand;
import com.tungsten.depbot.remediation.RemediationSourceException;
import com.tungsten.depbot.remediation.RemediationSourceReader;
import com.tungsten.depbot.remediation.RemediationSummary;
import com.tungsten.depbot.remediation.RemediationSummaryBuilder;
import com.tungsten.depbot.remediation.RemediationSummaryJsonRenderer;
import com.tungsten.depbot.remediation.RepositoryRefreshOutcomeJsonReader;
import com.tungsten.depbot.remediation.VulnerabilityRemediationOutcome;
import com.tungsten.depbot.remediation.VulnerabilityRemediationService;
import com.tungsten.depbot.report.ConsoleReporter;
import com.tungsten.depbot.report.RemediationRunSummaryCounts;
import com.tungsten.depbot.report.Severity;
import com.tungsten.depbot.report.actionable.ActionableReport;
import com.tungsten.depbot.run.RemediationRunService;
import com.tungsten.depbot.run.RunManifestWriteException;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * The whole developer-driven pipeline in one command: {@code scan}, then {@code plan-remediation}, then
 * each library through the two Claude roles.
 *
 * <p>The first two stages are the same {@code Command} objects the standalone commands use, so exception
 * handling, exit-code mapping and console output are identical either way. Everything after them is
 * {@link VulnerabilityRemediationService}: refresh refs, assess, apply the impact-score policy, verify the
 * ref through git, branch from the verified commit, implement, validate locally, keep or undo, restore.
 *
 * <p><strong>{@code --dependency groupId:artifactId} is the pilot form.</strong> The value is parsed
 * <em>before</em> {@code scan} runs, so a malformed one fails immediately having touched nothing. Scan and
 * plan still produce the complete, unfiltered documents; the filter only narrows which library is actually
 * worked on, which is what makes a pilot exactly one assessment, one branch and one implementation.
 *
 * <p>Nothing here pushes, opens a merge request, merges, triggers a build or rescans. Those are
 * deliberately not part of this command, and neither Claude role is permitted to do them either.
 */
public final class RemediateCommand {

    /** Written at the end of every run that got as far as attempting anything. */
    public static final String SUMMARY_FILE = "remediation-summary.json";

    private final ScanCommand scanCommand;
    private final RemediationPlanCommand planCommand;
    private final RemediationSourceReader sourceReader;
    private final VulnerabilityRemediationService remediationService;
    private final RemediationRunService runService;
    private final ConsoleReporter reporter;
    private final Clock clock;
    private final String model;
    private final Path repoPath;
    private final Supplier<String> runIdSupplier;
    private final GitLabPublicationService publicationService;
    private final RemediationSummaryJsonRenderer summaryRenderer = new RemediationSummaryJsonRenderer();
    private final CohortsIndexJsonReader cohortsIndexJsonReader = new CohortsIndexJsonReader();
    private final RepositoryRefreshOutcomeJsonReader repositoryRefreshOutcomeJsonReader =
            new RepositoryRefreshOutcomeJsonReader();

    /**
     * @param publicationService drives GitLab publication straight after a successful pipeline, reusing
     *                            the exact same service the standalone {@code publish --run <run-id>}
     *                            command uses -- see {@link #remediate} for exactly when and how it is
     *                            called, and {@code PublishCommand} for the retry path this never
     *                            replaces
     */
    public RemediateCommand(
            ScanCommand scanCommand,
            RemediationPlanCommand planCommand,
            RemediationSourceReader sourceReader,
            VulnerabilityRemediationService remediationService,
            RemediationRunService runService,
            ConsoleReporter reporter,
            Clock clock,
            String model,
            Path repoPath,
            Supplier<String> runIdSupplier,
            GitLabPublicationService publicationService) {
        this.scanCommand = Objects.requireNonNull(scanCommand, "scanCommand");
        this.planCommand = Objects.requireNonNull(planCommand, "planCommand");
        this.sourceReader = Objects.requireNonNull(sourceReader, "sourceReader");
        this.remediationService = Objects.requireNonNull(remediationService, "remediationService");
        this.runService = Objects.requireNonNull(runService, "runService");
        this.reporter = Objects.requireNonNull(reporter, "reporter");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.model = Objects.requireNonNull(model, "model");
        this.repoPath = Objects.requireNonNull(repoPath, "repoPath");
        this.runIdSupplier = Objects.requireNonNull(runIdSupplier, "runIdSupplier");
        this.publicationService = Objects.requireNonNull(publicationService, "publicationService");
    }

    /** Runs the whole plan, exactly as if {@code --dependency} had never been passed. */
    public ExitCode run() {
        return run(null, false);
    }

    /**
     * @param dependencyFilterRaw the raw {@code --dependency} value ({@code groupId:artifactId}), or
     *                            {@code null}/blank to work through every library in the report
     */
    public ExitCode run(String dependencyFilterRaw) {
        return run(dependencyFilterRaw, false);
    }

    /**
     * @param dependencyFilterRaw the raw {@code --dependency} value ({@code groupId:artifactId}), or
     *                            {@code null}/blank to work through every library in the report
     * @param noPublish           {@code --no-publish} -- runs the entire pipeline exactly as usual
     *                            (Mend retrieval, analysis, grouping, progressive cumulative remediation,
     *                            local validation, cumulative and final integration Jenkins, rejected-group
     *                            Human Review, every run artifact) but never calls {@link
     *                            GitLabPublicationService} afterward, so no push, branch publication, Merge
     *                            Request, Issue or comment is ever attempted. The run remains fully
     *                            publishable afterward via the standalone {@code publish --run <run-id>}.
     */
    public ExitCode run(String dependencyFilterRaw, boolean noPublish) {
        DependencyCoordinates pilotFilter;
        try {
            pilotFilter = parseFilter(dependencyFilterRaw);
        } catch (InvalidDependencyFilterException e) {
            reporter.printInvalidDependencyFilter(e.getMessage());
            return ExitCode.USAGE_ERROR;
        }

        ExitCode scanResult = scanCommand.run();
        if (scanResult != ExitCode.SUCCESS) {
            return scanResult;
        }
        ExitCode planResult = planCommand.run();
        if (planResult != ExitCode.SUCCESS) {
            return planResult;
        }

        List<VulnerabilityWorkItem> workItems;
        try {
            workItems = selectWorkItems(pilotFilter);
        } catch (RemediationSourceException e) {
            reporter.printRemediationSourceError(e.getMessage());
            return ExitCode.REMEDIATION_SOURCE_ERROR;
        }

        if (workItems.isEmpty()) {
            reporter.printRemediationRunSummary(new RemediationRunSummaryCounts(
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
            return ExitCode.SUCCESS;
        }

        return remediate(workItems, pilotFilter, noPublish);
    }

    private DependencyCoordinates parseFilter(String dependencyFilterRaw) {
        if (dependencyFilterRaw == null || dependencyFilterRaw.isBlank()) {
            return null;
        }
        DependencyCoordinates coordinates = DependencyCoordinates.parse(dependencyFilterRaw);
        reporter.printPilotDependencyFilter(coordinates.coordinates());
        return coordinates;
    }

    /**
     * Every library the published report describes, most severe first -- or exactly the one asked for.
     *
     * <p>A library the plan could not resolve a version for is <em>not</em> skipped. Under the
     * developer-driven model that decision belongs to the assessment: the plan's inability to derive a
     * version from Mend's fix text says nothing about whether a fix exists, and withholding such a library
     * would hide precisely the cases most worth a developer's judgement.
     */
    private List<VulnerabilityWorkItem> selectWorkItems(DependencyCoordinates pilotFilter) {
        ActionableReport report = sourceReader.readActionableReport();
        RemediationPlan plan = sourceReader.readPlan();

        if (pilotFilter != null) {
            return List.of(VulnerabilityWorkItemFactory
                    .forLibrary(report, plan, pilotFilter.groupId(), pilotFilter.artifactId())
                    .orElseThrow(() -> new RemediationSourceException(
                            "No library matching " + pilotFilter.coordinates()
                                    + " was found in the published vulnerability report.")));
        }

        List<VulnerabilityWorkItem> items =
                new ArrayList<>(VulnerabilityWorkItemFactory.from(report, plan));
        items.sort(Comparator
                .comparingInt((VulnerabilityWorkItem item) -> Severity.fromRaw(item.maxSeverity()).ordinal())
                .thenComparing(VulnerabilityWorkItem::coordinates));
        return items;
    }

    /**
     * Works through the selected libraries, reporting each as it goes and writing the run summary
     * afterwards -- including when a git-mechanical failure cut the run short, since the libraries already
     * attempted still have to be accounted for.
     */
    private ExitCode remediate(
            List<VulnerabilityWorkItem> workItems, DependencyCoordinates pilotFilter, boolean noPublish) {
        String runId = runIdSupplier.get();
        reporter.printRunId(runId);
        reporter.printRemediationRunStarting(workItems.size(), model, repoPath);

        List<VulnerabilityRemediationOutcome> outcomes = new ArrayList<>();
        ExitCode abortCode = null;
        try {
            outcomes = remediationService.remediateAll(runId, workItems);
            for (VulnerabilityRemediationOutcome outcome : outcomes) {
                report(outcome);
            }
        } catch (DirtyCheckoutException e) {
            reporter.printDirtyCheckoutError(e.getMessage());
            abortCode = ExitCode.GIT_OPERATION_ERROR;
        } catch (GitCommandException e) {
            reporter.printGitOperationError(e.getMessage());
            abortCode = ExitCode.GIT_OPERATION_ERROR;
        } catch (ConfigurationException e) {
            reporter.printConfigError(e.getMessage());
            abortCode = ExitCode.CONFIG_ERROR;
        } catch (RunManifestWriteException e) {
            reporter.printRunManifestWriteError(e.getMessage());
            abortCode = ExitCode.REPORT_WRITE_ERROR;
        }

        printSourceSynchronization(runId);

        RemediationSummary summary = RemediationSummaryBuilder.build(
                runId, generatedAt(), model, repoPath.toString(),
                pilotFilter == null ? null : pilotFilter.coordinates(), outcomes);

        Path summaryPath = runService.runDirectoryFor(runId).resolve(SUMMARY_FILE);
        try {
            runService.writeRunArtifact(summaryPath, summaryRenderer.render(summary));
        } catch (RunManifestWriteException e) {
            reporter.printRunManifestWriteError(e.getMessage());
            return abortCode == null ? ExitCode.REPORT_WRITE_ERROR : abortCode;
        }

        reporter.printRemediationRunSummary(new RemediationRunSummaryCounts(
                summary.librariesRemediatedCount(), summary.automaticGroupCount(), summary.commitCount(),
                summary.fullyValidatedCount(), summary.buildValidationFailedCount(),
                summary.isolatedJenkinsValidatedGroupCount(),
                summary.integrationJenkinsAttemptedCohortCount(), summary.integrationJenkinsSucceededCohortCount(),
                summary.readyToPublishGroupCount(), summary.humanReviewGroupCount(), summary.humanReviewLibraryCount(),
                summary.humanReviewRequiredCount(), summary.nothingToDoCount(), summary.needsAHumanCount(),
                summary.failureCount(), summary.automaticRejectedWithReportCount(),
                summary.automaticRejectedNoReportCount(), summary.analysisIncompleteBatchCount(),
                summary.analysisIncompleteFindingCount()));
        reporter.printRemediationRunArtifacts(summaryPath, runService.runDirectoryFor(runId));

        if (abortCode != null) {
            return abortCode;
        }

        ExitCode remediationCode = exitCodeFor(summary, outcomes);
        ExitCode publicationCode;
        String publicationResultLabel;
        if (noPublish) {
            // The gate: everything above already ran the full pipeline and wrote every run artifact --
            // this is the one and only place GitLabPublicationService would otherwise be reached.
            reporter.printPublicationSkipped();
            publicationCode = ExitCode.SUCCESS;
            publicationResultLabel = "SKIPPED (--no-publish)";
        } else {
            publicationCode = publish(runId, summary);
            publicationResultLabel = nameOf(publicationCode);
        }
        reporter.printFinalRunResult(nameOf(remediationCode), publicationResultLabel);
        return combineWithPublication(remediationCode, publicationCode);
    }

    /**
     * Reads back {@code repository-refresh.json}, written earlier in this same run by {@code
     * VulnerabilityRemediationService}, purely to report the verified source ref/SHA the run actually
     * synchronized to -- a display-only read; a failure to read it back never fails the command, since
     * the run's own outcome does not depend on this file being readable after the fact.
     */
    private void printSourceSynchronization(String runId) {
        Path path = runService.runDirectoryFor(runId).resolve(RepositoryRefreshOutcomeJsonReader.FILE_NAME);
        if (!Files.exists(path)) {
            return;
        }
        try {
            var refresh = repositoryRefreshOutcomeJsonReader.read(path);
            if (refresh.refreshed()) {
                reporter.printSourceSynchronization(refresh.sourceRef(), refresh.verifiedSourceSha());
            } else {
                reporter.printSourceSynchronizationFailed(refresh.message());
            }
        } catch (PublicationSourceException e) {
            // Display-only: the run's own artifacts already say what actually happened.
        }
    }

    /**
     * Publishes this run's automatic cohorts and Human Review groups to GitLab straight after a
     * completed pipeline, reusing the exact same {@link GitLabPublicationService} -- and therefore the
     * exact same eligibility/preflight/idempotency rules -- the standalone {@code publish --run <run-id>}
     * command uses. Reads {@code cohorts.json} back from disk rather than threading it through {@link
     * VulnerabilityRemediationService}'s return value, which is what makes an automatic publication here
     * and a later, manual retry via {@code publish} act on literally the same data.
     *
     * <p>A publication failure (network, permissions, a stale remote branch) never touches the
     * remediation run's own artifacts or exit code component: {@code cohorts.json}/{@code
     * remediation-summary.json} are already written, and the run remains fully retryable with {@code
     * publish --run <run-id>} regardless of what happens here.
     */
    private ExitCode publish(String runId, RemediationSummary summary) {
        Path cohortsPath = runService.runDirectoryFor(runId).resolve(CohortsIndexJsonReader.FILE_NAME);
        CohortsIndex cohortsIndex;
        try {
            cohortsIndex = cohortsIndexJsonReader.read(cohortsPath);
        } catch (PublicationSourceException e) {
            reporter.printPublicationSourceError(e.getMessage());
            return ExitCode.PUBLICATION_FAILED;
        }

        PublicationIndex publicationIndex = publicationService.publish(runId, cohortsIndex, summary);
        reporter.printPublicationResult(publicationIndex);

        boolean anyFailed = publicationIndex.cohorts().stream()
                .anyMatch(cohort -> cohort.status() == RemediationCohort.PublicationStatus.PUBLICATION_FAILED)
                || publicationIndex.humanReviewGroups().stream()
                        .anyMatch(group -> group.status() == IssuePublicationStatus.PUBLICATION_FAILED);
        return anyFailed ? ExitCode.PUBLICATION_FAILED : ExitCode.SUCCESS;
    }

    /**
     * A publication failure is reported distinctly, but never allowed to hide a genuine remediation
     * problem: {@link ExitCode#MANUAL_REMEDIATION_REQUIRED} (or a checkout that could not be restored)
     * still wins, since that is a worse, more actionable problem than GitLab being unreachable. Only when
     * remediation itself was otherwise clean, or waiting on nothing worse than Human Review, does a
     * publication failure become this run's own headline result -- exactly the case where a retry via
     * {@code publish --run <run-id>} is both sufficient and the obviously right next step.
     */
    private static ExitCode combineWithPublication(ExitCode remediationCode, ExitCode publicationCode) {
        if (publicationCode == ExitCode.PUBLICATION_FAILED
                && (remediationCode == ExitCode.SUCCESS || remediationCode == ExitCode.HUMAN_REVIEW_REQUIRED)) {
            return ExitCode.PUBLICATION_FAILED;
        }
        return remediationCode;
    }

    private static String nameOf(ExitCode code) {
        return code == ExitCode.SUCCESS ? "SUCCESS" : code.name();
    }

    /**
     * What is worth saying about a library <em>after</em> it finishes.
     *
     * <p>Deliberately only the two things a live progress listener does not carry: why it stopped, and a
     * checkout that could not be put back. Every step of the work has already been announced as it
     * happened, timestamped and with how long it took -- repeating all of it here would double the length
     * of a run's output and bury the one line that needs acting on.
     *
     * <p>Both go to stderr, so a run's problems survive piping stdout somewhere else.
     */
    private void report(VulnerabilityRemediationOutcome outcome) {
        if (outcome.stopReason() != null && !outcome.committed()) {
            reporter.printRemediationStopped(
                    outcome.coordinates(), outcome.reachedStage().name(), outcome.stopReason());
        }
        if (outcome.committed() && outcome.implementation() != null
                && outcome.implementation().fullBuildValidation() != null
                && !outcome.implementation().fullyBuildValidated()) {
            reporter.printBuildValidationFailed(
                    outcome.coordinates(), outcome.implementation().fullBuildValidation().reason());
        }
        if (outcome.humanReviewRequired()) {
            reporter.printHumanReviewRequired(outcome.coordinates(), outcome.automationSafetyReason());
        }
        if (outcome.restore() != null && !outcome.restore().restored()) {
            reporter.printRestoreWarningFor(outcome.coordinates(), outcome.restore().safeMessage());
        }
    }

    /**
     * Precedence: a checkout that could not be restored outranks everything, then a library that needed
     * work and did not get it (whether it never got a commit at all, or got one that then failed its
     * mandatory full build) -- a real problem, so {@link ExitCode#MANUAL_REMEDIATION_REQUIRED} wins even
     * if the same run also has a library merely waiting on review. Only once none of that is present does
     * a library committed and fully validated but flagged for human review before publication or merge
     * get its own, distinct {@link ExitCode#HUMAN_REVIEW_REQUIRED} -- a materially better situation than
     * {@code MANUAL_REMEDIATION_REQUIRED} that a run must not report identically to it. A run where every
     * library is either fully validated and safe to automate, or genuinely needed nothing, is the only one
     * that exits zero.
     *
     * <p>An incomplete Vulnerability Analysis ({@link RemediationSummary#analysisIncompleteBatchCount()})
     * is checked alongside {@code needsAHumanCount()}/{@code buildValidationFailedCount()}, not instead of
     * them: it is excluded from those counts precisely so it is not double-counted or reported as N
     * independent failures (see {@link RemediationSummaryEntry#needsAHuman()}), but it is exactly as real
     * a fail-closed, retry-me condition as either of them -- a run stuck this way must still exit
     * {@link ExitCode#MANUAL_REMEDIATION_REQUIRED}, never {@code SUCCESS}.
     */
    private static ExitCode exitCodeFor(
            RemediationSummary summary, List<VulnerabilityRemediationOutcome> outcomes) {
        boolean restoreFailed = outcomes.stream()
                .anyMatch(outcome -> outcome.restore() != null && !outcome.restore().restored());
        if (restoreFailed) {
            return ExitCode.GIT_OPERATION_ERROR;
        }
        if (summary.needsAHumanCount() > 0 || summary.buildValidationFailedCount() > 0
                || summary.analysisIncompleteBatchCount() > 0) {
            return ExitCode.MANUAL_REMEDIATION_REQUIRED;
        }
        if (summary.humanReviewRequiredCount() > 0) {
            return ExitCode.HUMAN_REVIEW_REQUIRED;
        }
        return ExitCode.SUCCESS;
    }

    private String generatedAt() {
        return DateTimeFormatter.ISO_INSTANT.format(clock.instant().truncatedTo(ChronoUnit.SECONDS));
    }
}
