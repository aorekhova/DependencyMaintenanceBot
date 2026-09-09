package com.tungsten.depbot.cli;

import com.tungsten.depbot.publication.GitLabPublicationService;
import com.tungsten.depbot.publication.IssuePublicationStatus;
import com.tungsten.depbot.publication.PublicationIndex;
import com.tungsten.depbot.publication.PublicationPreview;
import com.tungsten.depbot.remediation.CohortsIndex;
import com.tungsten.depbot.remediation.CohortsIndexJsonReader;
import com.tungsten.depbot.remediation.PublicationSourceException;
import com.tungsten.depbot.remediation.RemediationCohort;
import com.tungsten.depbot.remediation.RemediationSummary;
import com.tungsten.depbot.remediation.RemediationSummaryJsonReader;
import com.tungsten.depbot.report.ConsoleReporter;
import com.tungsten.depbot.run.RemediationRunService;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * The standalone publication step: reads a {@code remediate} run's own persisted {@code cohorts.json}
 * and {@code remediation-summary.json}, then either previews or actually carries out GitLab publication
 * -- entirely independent of {@code remediate} itself, so a temporary GitLab failure never requires
 * re-running Mend, Claude, local validation or Jenkins just to retry publication of an already fully
 * validated run. See {@link GitLabPublicationService}'s own javadoc for the publication semantics
 * themselves; this class only wires the CLI to it.
 *
 * <p>Non-interactive by design: {@code --dry-run} performs every read-only check and prints the exact
 * preview of what a real run would do, without a single mutating call; without it, {@code publish}
 * performs the real thing, with no prompt in between. The two are always separate, explicit invocations.
 */
public final class PublishCommand {

    private final GitLabPublicationService publicationService;
    private final RemediationRunService runService;
    private final CohortsIndexJsonReader cohortsIndexJsonReader;
    private final RemediationSummaryJsonReader remediationSummaryJsonReader;
    private final ConsoleReporter reporter;

    public PublishCommand(
            GitLabPublicationService publicationService,
            RemediationRunService runService,
            CohortsIndexJsonReader cohortsIndexJsonReader,
            RemediationSummaryJsonReader remediationSummaryJsonReader,
            ConsoleReporter reporter) {
        this.publicationService = Objects.requireNonNull(publicationService, "publicationService");
        this.runService = Objects.requireNonNull(runService, "runService");
        this.cohortsIndexJsonReader = Objects.requireNonNull(cohortsIndexJsonReader, "cohortsIndexJsonReader");
        this.remediationSummaryJsonReader =
                Objects.requireNonNull(remediationSummaryJsonReader, "remediationSummaryJsonReader");
        this.reporter = Objects.requireNonNull(reporter, "reporter");
    }

    public ExitCode run(String runId, boolean dryRun) {
        Objects.requireNonNull(runId, "runId");

        Path runDirectory = runService.runDirectoryFor(runId);
        Path cohortsPath = runDirectory.resolve(CohortsIndexJsonReader.FILE_NAME);
        Path summaryPath = runDirectory.resolve(RemediateCommand.SUMMARY_FILE);

        if (!Files.exists(cohortsPath) || !Files.exists(summaryPath)) {
            reporter.printPublicationSourceError("Run " + runId + " was not found, or never reached "
                    + "publication readiness (expected " + cohortsPath + " and " + summaryPath + ")");
            return ExitCode.PUBLICATION_SOURCE_ERROR;
        }

        CohortsIndex cohortsIndex;
        RemediationSummary summary;
        try {
            cohortsIndex = cohortsIndexJsonReader.read(cohortsPath);
            summary = remediationSummaryJsonReader.read(summaryPath);
        } catch (PublicationSourceException e) {
            reporter.printPublicationSourceError(e.getMessage());
            return ExitCode.PUBLICATION_SOURCE_ERROR;
        }

        if (dryRun) {
            PublicationPreview preview = publicationService.preview(runId, cohortsIndex, summary);
            reporter.printPublicationPreview(preview);
            return ExitCode.SUCCESS;
        }

        PublicationIndex index = publicationService.publish(runId, cohortsIndex, summary);
        reporter.printPublicationResult(index);
        return exitCodeFor(index);
    }

    private static ExitCode exitCodeFor(PublicationIndex index) {
        boolean anyFailed = index.cohorts().stream()
                .anyMatch(cohort -> cohort.status() == RemediationCohort.PublicationStatus.PUBLICATION_FAILED)
                || index.humanReviewGroups().stream()
                        .anyMatch(group -> group.status() == IssuePublicationStatus.PUBLICATION_FAILED);
        return anyFailed ? ExitCode.PUBLICATION_FAILED : ExitCode.SUCCESS;
    }
}
