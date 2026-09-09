package com.tungsten.depbot.report;

import com.tungsten.depbot.publication.PublicationIndex;
import com.tungsten.depbot.publication.PublicationPreview;
import com.tungsten.depbot.validation.MavenBuildValidationGate;

import java.io.PrintStream;
import java.nio.file.Path;
import java.util.List;

/**
 * Every piece of user-facing text this application produces.
 *
 * <p>Concentrating output here makes the "no credentials, no request bodies, no raw responses,
 * no stack traces" rule auditable in one file. All output is plain ASCII, because the Windows
 * console this tool targets reports a Cp1252 encoding and would mangle anything else.
 *
 * <p>Instances are immutable. A reporter starts with no knowledge of any secret; once
 * configuration has loaded, {@link #withSecrets(String...)} derives a <em>new</em> reporter
 * that masks those values. The original is never modified and there is no shared mutable state.
 */
public final class ConsoleReporter {

    public static final String USAGE = "Usage: java -jar dependency-maintenance-bot.jar "
            + "<remediate|scan|plan-remediation|prepare-remediation-branches|publish --run <run-id> [--dry-run]>";

    private final PrintStream out;
    private final PrintStream err;
    private final SecretRedactor redactor;

    /** Creates a reporter that knows no secrets yet. */
    public ConsoleReporter(PrintStream out, PrintStream err) {
        this(out, err, SecretRedactor.none());
    }

    private ConsoleReporter(PrintStream out, PrintStream err, SecretRedactor redactor) {
        this.out = out;
        this.err = err;
        this.redactor = redactor;
    }

    /** Returns a new reporter, sharing these streams, that masks the given values. */
    public ConsoleReporter withSecrets(String... secrets) {
        return new ConsoleReporter(out, err, SecretRedactor.of(secrets));
    }

    public void printUsage() {
        writeErr(USAGE);
    }

    public void printConfigError(String safeMessage) {
        writeErr("Configuration error: " + safeMessage);
    }

    public void printReport(SeverityCounts counts) {
        writeOut("Mend vulnerability check completed");
        writeOut("Total vulnerabilities: " + counts.total());
        writeOut("Critical: " + counts.criticalCount());
        writeOut("High: " + counts.highCount());
        writeOut("Medium: " + counts.mediumCount());
        writeOut("Low: " + counts.lowCount());
        writeOut("Other: " + counts.otherCount());
        writeOut("Process result: SUCCESS");
        writeOut("Security result: " + (counts.hasVulnerabilities()
                ? "VULNERABILITIES FOUND"
                : "NO VULNERABILITIES FOUND"));
    }

    /** Tells the operator exactly which files were written, rather than assuming the paths. */
    public void printReportLocations(Path jsonPath, Path markdownPath) {
        writeOut("Detailed report (JSON): " + jsonPath);
        writeOut("Detailed report (Markdown): " + markdownPath);
    }

    /**
     * A report write failed and cleanup succeeded, so no report files remain. Retrying is the
     * sensible next step.
     */
    public void printReportWriteError(String safeMessage) {
        writeErr("Report write error: " + safeMessage);
    }

    /**
     * A report write failed and cleanup was itself blocked, so the directory may hold a partial or
     * mismatched pair. Distinct from {@link #printReportWriteError} because this asks the operator
     * to inspect rather than simply retry; wording that implied a clean state would be misleading.
     */
    public void printReportPairStateUnknown(String safeMessage, List<Path> unreconciledPaths) {
        writeErr("Report write error: " + safeMessage);
        writeErr("WARNING: the current report file state could not be guaranteed.");
        if (unreconciledPaths != null) {
            for (Path path : unreconciledPaths) {
                writeErr("  Inspect before trusting: " + path);
            }
        }
    }

    /** Prints how many libraries landed in each remediation-plan bucket. */
    public void printRemediationPlanSummary(
            int criticalCount, int highCount, int mediumCount, int lowCount, int manualAnalysisRequiredCount) {
        writeOut("Remediation plan generated");
        writeOut("Critical libraries: " + criticalCount);
        writeOut("High libraries: " + highCount);
        writeOut("Medium libraries: " + mediumCount);
        writeOut("Low libraries: " + lowCount);
        writeOut("Manual analysis required: " + manualAnalysisRequiredCount);
    }

    /** Tells the operator exactly which remediation plan files were written. */
    public void printRemediationPlanLocations(Path jsonPath, Path markdownPath) {
        writeOut("Remediation plan (JSON): " + jsonPath);
        writeOut("Remediation plan (Markdown): " + markdownPath);
    }

    /**
     * {@code plan-remediation} could not read or understand its source report. The message never
     * includes file content -- only the path and what went wrong -- because the source report,
     * while already redacted, is still report data.
     */
    public void printRemediationSourceError(String safeMessage) {
        writeErr("Remediation plan error: " + safeMessage);
    }

    /**
     * Announces a {@code remediate --dependency} pilot run, printed once, before scan even starts,
     * so the operator sees immediately what is (and is not) about to be touched.
     */
    public void printPilotDependencyFilter(String coordinates) {
        writeOut("Pilot dependency filter:");
        writeOut(coordinates);
    }

    /** Which severity bucket the piloted library was really in, and how many units it produced (always 1). */
    public void printPilotSelection(String severity, int unitCount) {
        writeOut("");
        writeOut("Selected severity: " + severity);
        writeOut("Selected units: " + unitCount);
    }

    /** The {@code --dependency} value could not be parsed as {@code groupId:artifactId}. */
    public void printInvalidDependencyFilter(String safeMessage) {
        writeErr("Invalid --dependency value: " + safeMessage);
    }

    /** The {@code --dependency} coordinates do not match any library that can become a remediation unit. */
    public void printDependencyNotFoundError(String safeMessage) {
        writeErr("Dependency filter error: " + safeMessage);
    }

    /** The id of this remediation run, shared by every branch it creates. */
    public void printRunId(String runId) {
        writeOut("Run ID: " + runId);
    }

    /** The commit every remediation branch created in this run was branched from. */
    public void printBaseCommit(String sha) {
        writeOut("Base commit (origin/master): " + sha);
    }

    /** A severity group had no libraries, so no branch was created for it. */
    public void printSeverityGroupEmpty(String group) {
        writeOut(capitalize(group) + ": no libraries, skipped");
    }

    /** A branch was created for one severity group. No worktree or checkout is created alongside it. */
    public void printBranchCreated(String group, String branchName) {
        writeOut(capitalize(group) + ": created branch " + branchName);
    }

    /** A severity group's branch could not be created; other groups are unaffected. */
    public void printSeverityGroupFailed(String group, String safeMessage) {
        writeErr(capitalize(group) + ": FAILED - " + safeMessage);
    }

    /**
     * A {@code git} command failed outside any single unit -- {@code fetch} or {@code rev-parse}
     * against the shared base commit before any branch was attempted, or a checkout switch, staging,
     * commit or rollback that itself failed mid-run. Either way the checkout can no longer be trusted
     * to continue on its own, so the run stops here.
     */
    public void printGitOperationError(String safeMessage) {
        writeErr("Git operation error: " + safeMessage);
    }

    /** The checkout was not clean (or a merge/rebase/cherry-pick was left mid-flight) before the run began. */
    public void printDirtyCheckoutError(String safeMessage) {
        writeErr("Dirty checkout: " + safeMessage);
    }

    /**
     * The checkout could not be safely returned to its original branch after the run. Nothing was
     * forced or discarded -- the checkout was left exactly as it is. Loud and distinct from a plain
     * error because the run's own outcome (which units committed or rolled back) is still valid; only
     * the housekeeping step of restoring the original checkout did not complete.
     */
    public void printRestoreWarning(String safeMessage) {
        writeErr("WARNING: could not safely restore the original checkout.");
        writeErr("  " + safeMessage);
    }

    /** How many remediation units were created for this run, and how many libraries need a human look first. */
    public void printRunManifestSummary(int unitCount, int manualAnalysisRequiredCount) {
        writeOut("Remediation units created: " + unitCount);
        writeOut("Manual analysis required (not automated): " + manualAnalysisRequiredCount);
    }

    /** Where the run manifest was written. */
    public void printRunManifestLocation(Path manifestPath) {
        writeOut("Run manifest: " + manifestPath);
    }

    public void printRunManifestWriteError(String safeMessage) {
        writeErr("Run manifest write error: " + safeMessage);
    }

    /** Names the model up front, so it is visible before any work starts rather than only in the manifest. */
    public void printExecutionStarting(int unitCount, String model) {
        writeOut("Running Claude Code on " + unitCount + " unit(s) with model: " + model);
    }

    public void printUnitStarting(String severity, String coordinates) {
        writeOut("  [" + severity + "] " + coordinates + ": running");
    }

    public void printUnitFinished(String coordinates, String status) {
        writeOut("  " + coordinates + ": " + status);
    }

    /** Failure detail goes to stderr so a run's problems survive piping stdout somewhere else. */
    public void printUnitFailureReason(String coordinates, String safeMessage) {
        writeErr("  " + coordinates + ": " + safeMessage);
    }

    /**
     * Deliberately worded as "pending validation" rather than "succeeded": nothing has built or
     * tested the result yet, so claiming success here would overstate what is known. Printed
     * whenever execution ran at all, whether every unit committed or some rolled back.
     */
    public void printExecutionSummary(int committedPendingValidation, int rolledBack) {
        writeOut("Units committed (pending validation): " + committedPendingValidation);
        writeOut("Units rolled back: " + rolledBack);
        writeOut("NOTE: dependency:tree, compile, tests and package were not run against these changes.");
        writeOut("Treat this as a starting point for manual or later automated verification, "
                + "not something ready to push.");
    }

    private static String capitalize(String value) {
        return value.isEmpty() ? value : Character.toUpperCase(value.charAt(0)) + value.substring(1);
    }

    // ---- the developer-driven remediation flow -------------------------------------------------

    public void printRemediationRunStarting(int libraryCount, String model, Path repoPath) {
        writeOut("Remediating " + libraryCount + " library/libraries with model: " + model);
        writeOut("Repository: " + repoPath);
    }

    /** Named before the assessment runs, so a fetch problem is obviously the bot's own step. */
    public void printRefsRefreshed(String coordinates) {
        writeOut("  " + coordinates + ": remote refs refreshed");
    }

    public void printRefsRefreshFailed(String coordinates, String safeMessage) {
        writeErr("  " + coordinates + ": stopped before the assessment -- " + safeMessage);
    }

    public void printAssessmentResult(
            String coordinates, String conclusion, Integer impactScore, String verdict) {
        writeOut("  " + coordinates + ": assessment " + conclusion
                + (impactScore == null ? "" : ", impact " + impactScore)
                + " -> " + verdict);
    }

    /**
     * Prints both the ref the assessment asked for and the commit git resolved for it. Showing them
     * together is what makes it visible on the console that the bot resolved the ref itself.
     */
    public void printSourceRefVerified(String coordinates, String resolvedRef, String resolvedSha) {
        writeOut("  " + coordinates + ": source ref " + resolvedRef + " -> " + resolvedSha);
    }

    public void printSourceRefRejected(String coordinates, String safeMessage) {
        writeErr("  " + coordinates + ": source ref not usable -- " + safeMessage);
    }

    public void printRemediationBranchCreated(String coordinates, String branchName) {
        writeOut("  " + coordinates + ": branch " + branchName);
    }

    public void printImplementationResult(String coordinates, String conclusion, String disposition) {
        writeOut("  " + coordinates + ": implementation "
                + (conclusion == null ? "produced no usable report" : conclusion)
                + " -> " + disposition);
    }

    public void printValidationResult(String coordinates, String status, String safeMessage) {
        writeOut("  " + coordinates + ": validation " + status);
        writeOut("      " + safeMessage);
    }

    public void printRemediationStopped(String coordinates, String stage, String safeMessage) {
        writeErr("  " + coordinates + ": stopped at " + stage + " -- " + safeMessage);
    }

    /**
     * The commit stands -- it is not undone by a failing build -- but it did not pass the mandatory full
     * local build. Printed to stderr like {@link #printRemediationStopped}, even though this is not a
     * stop: the run kept going, but this is exactly the kind of line that must survive piping stdout
     * elsewhere.
     */
    public void printBuildValidationFailed(String coordinates, String safeMessage) {
        writeErr("  " + coordinates + ": committed, but the full build did not pass -- " + safeMessage);
    }

    /**
     * The analysis judged this one unsafe to trust to automation -- no implementation ever ran, and
     * nothing about the repository was changed. A read-only Human Review Report was prepared instead, for
     * a person to act on. Printed to stderr like {@link #printBuildValidationFailed}, for the same
     * reason: it must survive piping stdout elsewhere.
     */
    public void printHumanReviewRequired(String coordinates, String safeMessage) {
        writeErr("  " + coordinates + ": needs human review -- a Human Review Report was prepared, no "
                + "automatic change was made -- " + safeMessage);
    }

    public void printRestoreWarningFor(String coordinates, String safeMessage) {
        writeErr("  " + coordinates + ": " + safeMessage);
    }

    /**
     * The counts, and then plainly what has and has not been established.
     *
     * <p>Libraries, remediation groups and commits are three deliberately distinct numbers, never
     * folded into one another: several libraries of one Claude-defined group share exactly one commit,
     * so a run's "libraries remediated" count is routinely larger than its "automatic groups"/"commits"
     * count, and that is correct, not a discrepancy to explain away. "Fully validated" means a full
     * local build actually confirmed the change; isolated and final integration Jenkins validation are
     * each their own, separately reported gate -- a group passing isolation is never, by itself, reason
     * to call the run's commits "ready to publish".
     */
    public void printRemediationRunSummary(RemediationRunSummaryCounts counts) {
        writeOut("Libraries remediated: " + counts.librariesRemediated());
        writeOut("Automatic remediation groups: " + counts.automaticGroups());
        writeOut("Commits: " + counts.commits());
        writeOut("Fully validated (committed and built successfully): " + counts.fullyValidated());
        writeOut("Build validation failed (commit kept for diagnosis): " + counts.buildValidationFailed());
        writeOut("Cumulative Jenkins validated groups: " + counts.isolatedJenkinsValidatedGroups());
        writeOut("Final integration Jenkins: " + counts.integrationJenkinsSucceededCohorts() + " of "
                + counts.integrationJenkinsAttemptedCohorts() + " cohort(s) succeeded");
        writeOut("Ready to publish (both Jenkins gates succeeded): " + counts.readyToPublishGroups()
                + " group(s), " + counts.readyToPublishGroups() + " commit(s)");
        writeOut("Human Review groups: " + counts.humanReviewGroups());
        writeOut("Human Review libraries: " + counts.humanReviewLibraries());
        writeOut("Needs human review (Human Review Report prepared, no automatic change made): "
                + counts.humanReviewRequired());
        writeOut("Nothing to remediate: " + counts.nothingToDo());
        writeOut("Needs a human: " + counts.needsAHuman());
        writeOut("  of which, automatic attempt rejected but a Human Review report was produced "
                + "(handled, not an unexplained failure): " + counts.automaticRejectedWithReport());
        writeOut("  of which, no report could be produced either (needs direct investigation): "
                + counts.automaticRejectedNoReport());
        writeOut("Failures (build validation failed, or needs a human with no report at all): "
                + counts.failures());
        writeOut("Vulnerability Analysis incomplete (not counted as failures above): "
                + counts.analysisIncompleteBatches() + " assessment(s), "
                + counts.analysisIncompleteFindings() + " finding(s) not routed");
        writeOut("NOTE: the dependency-resolution gate resolved the tree offline, then a full `mvn "
                + String.join(" ", MavenBuildValidationGate.BUILD_ARGS) + "` was run on every committed "
                + "change. Nothing was pushed, merged or proposed for review.");
    }

    /** Where to look afterwards. Printed last so it is the final thing on screen. */
    public void printRemediationRunArtifacts(Path summaryPath, Path runDirectory) {
        writeOut("Run summary: " + summaryPath);
        writeOut("Run artifacts: " + runDirectory);
    }

    // ---- GitLab publication ---------------------------------------------------------------------

    /** {@code publish} could not find or understand the named run's own persisted artifacts. */
    public void printPublicationSourceError(String safeMessage) {
        writeErr("Publication source error: " + safeMessage);
    }

    /**
     * The managed checkout was genuinely brought to the verified tip of its own remote counterpart
     * before anything else in this run touched it -- printed first, so the source everything else in the
     * run acted on is never left implicit.
     */
    public void printSourceSynchronization(String verifiedSourceRef, String verifiedSourceSha) {
        writeOut("Source synchronization: SUCCESS");
        writeOut("Verified source ref: " + verifiedSourceRef);
        writeOut("Verified source SHA: " + verifiedSourceSha);
    }

    /** The managed checkout could not be safely synchronized -- nothing after this point ran. */
    public void printSourceSynchronizationFailed(String safeMessage) {
        writeErr("Source synchronization: FAILED -- " + safeMessage);
    }

    /**
     * The very last thing a {@code remediate} run prints: the one-line remediation and publication
     * verdicts side by side, and an explicit, unmissable reminder that this application never merges
     * anything itself.
     */
    public void printFinalRunResult(String remediationResult, String publicationResult) {
        writeOut("");
        writeOut("Automatic merge: DISABLED");
        writeOut("");
        writeOut("Run result: " + remediationResult);
        writeOut("Publication result: " + publicationResult);
    }

    /**
     * Everything {@code publish --dry-run} would do, with no changes made -- one section per cohort
     * (never collapsed into a single run-wide branch/target, since one run can have several), then every
     * Human Review group. Credentials are never in {@link PublicationPreview} to begin with, so there is
     * nothing to redact here.
     */
    public void printPublicationPreview(PublicationPreview preview) {
        writeOut("Publishing run " + preview.runId() + " (DRY RUN -- no changes made)");
        for (PublicationPreview.CohortPreview cohort : preview.cohorts()) {
            writeOut("");
            writeOut("Cohort: " + cohort.sourceRef() + " @ " + cohort.sourceSha());
            writeOut("  Local branch:  " + cohort.localBranch());
            writeOut("  Remote branch: " + cohort.remoteBranch());
            writeOut("  Target branch: " + cohort.targetBranch());
            if (!cohort.eligible()) {
                writeOut("  NOT ELIGIBLE -- " + cohort.ineligibleReason());
                continue;
            }
            writeOut("  Expected HEAD SHA: " + cohort.expectedHeadSha());
            writeOut("  Groups (" + cohort.groupIds().size() + "): " + String.join(", ", cohort.groupIds()));
            writeOut("  Commits (" + cohort.commitShas().size() + "): " + String.join(", ", cohort.commitShas()));
            writeOut(cohort.existingMergeRequestState() == null
                    ? "  Merge Request: would be created"
                    : "  Existing Merge Request: " + cohort.existingMergeRequestState()
                            + " -- " + cohort.existingMergeRequestUrl());
        }
        writeOut("");
        writeOut("Human Review groups (" + preview.humanReviewGroups().size() + "):");
        for (PublicationPreview.HumanReviewGroupPreview group : preview.humanReviewGroups()) {
            writeOut("  " + String.join(", ", group.memberCoordinates()) + " -> "
                    + (group.existingIssueState() == null
                            ? "would create a new issue"
                            : "existing issue " + group.existingIssueState() + " -- " + group.existingIssueUrl()));
        }
        writeOut("");
        writeOut("No automatic merge will be performed.");
    }

    /**
     * {@code remediate --no-publish} ran the whole pipeline -- including every local commit, branch and
     * validation gate -- but never called {@link com.tungsten.depbot.publication.GitLabPublicationService}
     * at all: no push, no branch publication, no Merge Request, no Issue, no comment. The run remains
     * fully publishable afterward through the ordinary {@code publish --run <run-id>} command.
     */
    public void printPublicationSkipped() {
        writeOut("Publication: SKIPPED (--no-publish)");
    }

    /** What {@code publish} actually did -- real cohort/Human Review outcomes, after the fact. */
    public void printPublicationResult(PublicationIndex index) {
        writeOut("Publishing run " + index.runId());
        for (PublicationIndex.CohortPublication cohort : index.cohorts()) {
            writeOut("  " + cohort.branchName() + ": " + cohort.status()
                    + (cohort.mergeRequestUrl() != null ? " -- " + cohort.mergeRequestUrl() : "")
                    + (cohort.errorMessage() != null ? " (" + cohort.errorMessage() + ")" : ""));
        }
        for (PublicationIndex.HumanReviewPublication group : index.humanReviewGroups()) {
            writeOut("  " + String.join(", ", group.memberCoordinates()) + ": " + group.status()
                    + (group.issueUrl() != null ? " -- " + group.issueUrl() : "")
                    + (group.errorMessage() != null ? " (" + group.errorMessage() + ")" : ""));
        }
        writeOut("No automatic merge will be performed.");
    }

    /** The message originates from Mend, so redaction is what makes this safe. */
    public void printApiError(int errorCode, String message) {
        writeErr("Mend API error " + errorCode + ": " + message);
    }

    public void printNetworkError(String safeMessage) {
        writeErr("Could not complete the Mend request: " + safeMessage);
    }

    public void printMalformedResponseError() {
        writeErr("Mend returned a response that could not be understood. "
                + "The response content is not shown because it may contain sensitive data.");
    }

    public void printUnexpectedError() {
        writeErr("An unexpected internal error occurred. No details are shown to avoid "
                + "leaking sensitive data.");
    }

    /**
     * The same refusal to print details, plus where a developer can read them.
     *
     * <p>Naming the file is not a leak: the path is chosen by this application, and what the file contains
     * has already been redacted. Printing nothing at all is what made a real pilot failure impossible to
     * diagnose.
     */
    public void printUnexpectedError(Path diagnosticLogPath) {
        printUnexpectedError();
        if (diagnosticLogPath != null) {
            writeErr("Diagnostic details (safe to share, credentials masked): " + diagnosticLogPath);
        } else {
            writeErr("A diagnostic log could not be written either; re-run with the reports directory "
                    + "writable to capture one.");
        }
    }

    /** A step that may take minutes is starting. Timestamped, because the gap to the next line is the point. */
    public void printStepStarting(String timestamp, String coordinates, String step, String detail) {
        writeOut("[" + timestamp + "] " + coordinates + " -- " + step
                + (detail == null || detail.isBlank() ? "" : ": " + detail));
    }

    /** A step finished, with how long it took, so a slow run can be told from a stuck one afterwards. */
    public void printStepFinished(
            String timestamp, String coordinates, String step, String elapsed, String outcome) {
        writeOut("[" + timestamp + "] " + coordinates + " -- " + step + " done in " + elapsed
                + (outcome == null || outcome.isBlank() ? "" : ": " + outcome));
    }

    /**
     * A step that can run for a long time is still going. Printed periodically so a slow build and a
     * hung one look different on screen instead of identical.
     */
    public void printStepHeartbeat(
            String timestamp, String coordinates, String step, String elapsed, String detail) {
        writeOut("[" + timestamp + "] " + coordinates + " -- " + step + " still running (" + elapsed
                + " elapsed)" + (detail == null || detail.isBlank() ? "" : ": " + detail));
    }

    private void writeOut(String text) {
        out.println(redactor.redact(text));
        out.flush();
    }

    private void writeErr(String text) {
        err.println(redactor.redact(text));
        err.flush();
    }
}
