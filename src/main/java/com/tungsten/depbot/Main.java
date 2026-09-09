package com.tungsten.depbot;

import com.tungsten.depbot.assessment.BatchAnalysisPromptRenderer;
import com.tungsten.depbot.assessment.BatchAnalysisService;
import com.tungsten.depbot.claude.ClaudeCodeExecutor;
import com.tungsten.depbot.claude.ClaudeConfig;
import com.tungsten.depbot.claude.ClaudeProcessRunner;
import com.tungsten.depbot.cli.ExitCode;
import com.tungsten.depbot.cli.PrepareRemediationBranchesCommand;
import com.tungsten.depbot.cli.PublishCommand;
import com.tungsten.depbot.cli.RemediateCommand;
import com.tungsten.depbot.cli.ScanCommand;
import com.tungsten.depbot.config.ConfigurationException;
import com.tungsten.depbot.config.EnvConfig;
import com.tungsten.depbot.diagnostics.DiagnosticLog;
import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.git.GitWorktreeConfig;
import com.tungsten.depbot.git.ManagedRepositoryRefresher;
import com.tungsten.depbot.git.RemediationBranchPreparationService;
import com.tungsten.depbot.git.RemediationChangeCommitter;
import com.tungsten.depbot.git.RemediationCheckoutManager;
import com.tungsten.depbot.git.RemediationDiffPolicy;
import com.tungsten.depbot.git.RemoteRefsRefresher;
import com.tungsten.depbot.git.SourceRefVerifier;
import com.tungsten.depbot.humanreview.HumanReviewPromptRenderer;
import com.tungsten.depbot.humanreview.HumanReviewService;
import com.tungsten.depbot.implementation.ImplementationPromptRenderer;
import com.tungsten.depbot.implementation.RemediationImplementationService;
import com.tungsten.depbot.jenkins.JenkinsApiClient;
import com.tungsten.depbot.jenkins.JenkinsConfig;
import com.tungsten.depbot.jenkins.JenkinsValidationService;
import com.tungsten.depbot.mend.MendClient;
import com.tungsten.depbot.mend.MendGateway;
import com.tungsten.depbot.progress.ConsoleProgressListener;
import com.tungsten.depbot.progress.RemediationProgressListener;
import com.tungsten.depbot.publication.GitLabApiClient;
import com.tungsten.depbot.publication.GitLabConfig;
import com.tungsten.depbot.publication.GitLabPublicationService;
import com.tungsten.depbot.remediation.CohortsIndexJsonReader;
import com.tungsten.depbot.remediation.RemediationPlanCommand;
import com.tungsten.depbot.remediation.RemediationPlanService;
import com.tungsten.depbot.remediation.RemediationSourceReader;
import com.tungsten.depbot.remediation.RemediationSummaryJsonReader;
import com.tungsten.depbot.remediation.VulnerabilityRemediationService;
import com.tungsten.depbot.report.ConsoleReporter;
import com.tungsten.depbot.report.SecretRedactor;
import com.tungsten.depbot.report.actionable.ActionableReportService;
import com.tungsten.depbot.report.actionable.ReportDestination;
import com.tungsten.depbot.run.RemediationRunService;
import com.tungsten.depbot.run.RunIds;
import com.tungsten.depbot.validation.DependencyResolutionGate;
import com.tungsten.depbot.validation.MavenBuildValidationGate;

import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Clock;
import java.util.function.Supplier;

/**
 * Command-line entry point.
 *
 * <p>Usage: {@code java -jar dependency-maintenance-bot.jar
 * <remediate|scan|plan-remediation|prepare-remediation-branches>}
 *
 * <p>{@link #run}, {@link #runPlanRemediation}, {@link #runPrepareRemediationBranches} and
 * {@link #runRemediate} contain the dispatch logic for each command and return an {@link ExitCode};
 * {@link #main} is the only place that calls {@code System.exit}. Keeping them apart is what lets tests
 * assert on exit codes without terminating the test JVM.
 *
 * <p>{@code remediate} is the whole developer-driven pipeline in one command: {@code scan}, then
 * {@code plan-remediation}, then each library through both Claude roles -- assessment, then
 * implementation on a branch cut from the commit git resolved for the ref the assessment identified. See
 * {@link RemediateCommand} and {@link VulnerabilityRemediationService}.
 *
 * <p>{@code remediate --dependency groupId:artifactId} is a pilot run limited to exactly one library (for
 * example {@code remediate --dependency org.bouncycastle:bcprov-jdk18on}): one assessment, one branch, one
 * implementation, everything else in the report left untouched.
 *
 * <p>{@code remediate --no-publish} (composable with {@code --dependency}, e.g. {@code remediate
 * --dependency groupId:artifactId --no-publish}) is a pilot/debug mode: the entire pipeline runs exactly
 * as usual -- Mend retrieval, analysis, grouping, progressive cumulative remediation, local validation,
 * cumulative and final integration Jenkins, rejected-group Human Review, every run artifact -- but {@link
 * RemediateCommand} never calls {@link com.tungsten.depbot.publication.GitLabPublicationService}
 * afterward, so no push, branch publication, Merge Request, Issue or comment is ever attempted. Local
 * remediation/candidate branches and commits are unaffected. The run remains fully publishable afterward
 * through the standalone {@code publish --run <run-id>} command.
 *
 * <p>{@code prepare-remediation-branches} and its deprecated {@code create-remediation-worktrees} alias
 * are <strong>legacy</strong>. They create one branch per severity from {@code origin/master} and write
 * the pre-two-phase task files, and nothing in {@code remediate} uses them any more -- a remediation
 * branch is now cut per library from a ref an assessment identified and git verified. They are kept only
 * as a standalone git-only utility.
 *
 * <p>Neither {@code plan-remediation} nor {@code prepare-remediation-branches} touches {@link EnvConfig},
 * {@link MendGateway} or an {@link HttpClient}: both only read a local file an earlier command already
 * wrote, so {@link #main} builds none of the scan-only dependencies when either is requested on its own.
 */
public final class Main {

    static final String SCAN_COMMAND = "scan";
    static final String PLAN_REMEDIATION_COMMAND = "plan-remediation";
    static final String PREPARE_REMEDIATION_BRANCHES_COMMAND = "prepare-remediation-branches";
    static final String CREATE_REMEDIATION_WORKTREES_COMMAND = "create-remediation-worktrees";
    static final String REMEDIATE_COMMAND = "remediate";
    static final String DEPENDENCY_FLAG = "--dependency";
    static final String NO_PUBLISH_FLAG = "--no-publish";
    static final String PUBLISH_COMMAND = "publish";
    static final String RUN_FLAG = "--run";
    static final String DRY_RUN_FLAG = "--dry-run";

    private Main() {
    }

    public static void main(String[] args) {
        ConsoleReporter reporter = new ConsoleReporter(System.out, System.err);
        System.exit(guarded(() -> dispatch(args, reporter), reporter, diagnosticLog(), describe(args))
                .value());
    }

    private static ExitCode dispatch(String[] args, ConsoleReporter reporter) {
        if (isCommand(args, PLAN_REMEDIATION_COMMAND)) {
            return runPlanRemediation(args, reporter, planService());
        }
        if (isCommand(args, PREPARE_REMEDIATION_BRANCHES_COMMAND)
                || isCommand(args, CREATE_REMEDIATION_WORKTREES_COMMAND)) {
            return runPrepareRemediationBranches(args, reporter, branchCommand(runService(), reporter));
        }
        if (isRemediateCommand(args)) {
            try (HttpClient httpClient = MendClient.defaultHttpClient()) {
                return runRemediate(args, reporter, remediateCommand(new MendClient(httpClient), reporter,
                        GitWorktreeConfig::fromEnvironment, ClaudeConfig::fromEnvironment,
                        () -> JenkinsConfig.fromEnvironment(System.getenv()),
                        () -> GitLabConfig.fromEnvironment(System.getenv())));
            }
        }
        if (isPublishCommand(args)) {
            return runPublish(args, reporter, publishCommand(
                    reporter, GitWorktreeConfig::fromEnvironment, () -> GitLabConfig.fromEnvironment(System.getenv())));
        }
        try (HttpClient httpClient = MendClient.defaultHttpClient()) {
            return run(args, EnvConfig::fromEnvironment, new MendClient(httpClient), reporter,
                    reportService());
        }
    }

    /**
     * Runs {@code action} and turns anything that escapes it into an exit code.
     *
     * <p><strong>A configuration problem is a configuration problem wherever it surfaces.</strong> That
     * distinction used to be made only inside the commands, which was fine while every command read its
     * configuration lazily -- {@code scan} is handed a {@code Supplier} and resolves it inside
     * {@link ScanCommand}, where a {@link ConfigurationException} is caught and reported properly.
     * {@code remediate} cannot do that: it needs the repository path and the Claude settings to build its
     * pipeline at all, so it reads them while wiring, <em>outside</em> any command's own handling. A
     * missing {@code WEBAPP_REPO_PATH} therefore reached the last-resort handler and was reported as an
     * internal error -- an unactionable message for the one class of failure that is entirely the
     * operator's to fix.
     *
     * <p>Anything else really is unexpected, and gets the message that says nothing plus a diagnostic file
     * that says everything safely. {@code Throwable}, not {@code Exception}: without this the JVM would
     * print a full stack trace and exit 1, which both leaks internals and collides with the usage exit
     * code.
     */
    static ExitCode guarded(
            Supplier<ExitCode> action, ConsoleReporter reporter, DiagnosticLog diagnostics, String context) {
        try {
            return action.get();
        } catch (ConfigurationException e) {
            reporter.printConfigError(e.getMessage());
            return ExitCode.CONFIG_ERROR;
        } catch (Throwable t) {
            reporter.printUnexpectedError(diagnostics.record(context, t));
            return ExitCode.UNEXPECTED_ERROR;
        }
    }

    /**
     * The command line, as something safe to write into a diagnostic file: the command and its arguments,
     * which this application defines and the operator typed. No environment is involved.
     */
    static String describe(String[] args) {
        return args == null || args.length == 0 ? "no command" : String.join(" ", args);
    }

    /**
     * Where an internal failure is recorded, with a redactor seeded from the credential variables.
     *
     * <p>Those values are read only to be used as masks and are never written anywhere. Reading them here
     * rather than through {@link EnvConfig} is deliberate: this has to work when configuration is exactly
     * what is broken, so it must not be able to throw.
     */
    private static DiagnosticLog diagnosticLog() {
        return new DiagnosticLog(
                Path.of(ReportDestination.DEFAULT_DIRECTORY, DiagnosticLog.DEFAULT_DIRECTORY_NAME),
                Clock.systemUTC(),
                SecretRedactor.of(System.getenv(EnvConfig.MEND_USER_KEY),
                        System.getenv(EnvConfig.MEND_PROJECT_TOKEN)));
    }

    /**
     * Assembles the developer-driven pipeline.
     *
     * <p>Reads {@link GitWorktreeConfig} and {@link ClaudeConfig} here rather than deeper down, so a
     * missing {@code WEBAPP_REPO_PATH} is a configuration error reported before anything is scanned.
     *
     * <p>{@code jenkinsConfigSource} and {@code gitLabConfigSource} are read strictly last, in that
     * order, after the other two -- the same injectable-{@code Supplier} test seam they already use --
     * so the existing {@code MainInternalErrorTest} scenarios that inject a throwing {@code
     * GitWorktreeConfig}/{@code ClaudeConfig}/{@code JenkinsConfig} supplier keep failing on their own
     * supplier, before a later one is ever reached.
     */
    static RemediateCommand remediateCommand(
            MendGateway gateway,
            ConsoleReporter reporter,
            Supplier<GitWorktreeConfig> worktreeConfigSource,
            Supplier<ClaudeConfig> claudeConfigSource,
            Supplier<JenkinsConfig> jenkinsConfigSource,
            Supplier<GitLabConfig> gitLabConfigSource) {
        Clock clock = Clock.systemUTC();
        // Read up front, so a missing WEBAPP_REPO_PATH stops the run before a Mend call is spent on it.
        // What makes that safe is guarded(): the ConfigurationException it throws is reported as one.
        Path repoPath = worktreeConfigSource.get().repoPath();
        ClaudeConfig claudeConfig = claudeConfigSource.get();
        JenkinsConfig jenkinsConfig = jenkinsConfigSource.get();
        GitLabConfig gitLabConfig = gitLabConfigSource.get();
        RemediationRunService runService = runService();
        RemediationProgressListener progress = new ConsoleProgressListener(reporter, clock);

        ScanCommand scanCommand = new ScanCommand(
                EnvConfig::fromEnvironment, gateway, reporter, reportService());
        RemediationPlanCommand planCommand = new RemediationPlanCommand(planService(), reporter);

        GitCommandRunner git = new GitCommandRunner();
        ClaudeCodeExecutor executor =
                new ClaudeCodeExecutor(claudeConfig, new ClaudeProcessRunner(), runService, clock);
        JenkinsValidationService jenkinsValidationService = new JenkinsValidationService(
                new JenkinsApiClient(jenkinsConfig), jenkinsConfig, git, runService, progress);

        VulnerabilityRemediationService remediationService = new VulnerabilityRemediationService(
                repoPath,
                git,
                new RemoteRefsRefresher(git),
                new ManagedRepositoryRefresher(git, new SourceRefVerifier(git)),
                new RemediationCheckoutManager(git),
                new SourceRefVerifier(git),
                new BatchAnalysisService(executor, claudeConfig, runService,
                        new BatchAnalysisPromptRenderer()),
                new RemediationImplementationService(executor, claudeConfig, runService,
                        new ImplementationPromptRenderer(), git,
                        new RemediationChangeCommitter(git, new RemediationDiffPolicy()),
                        new DependencyResolutionGate(),
                        new MavenBuildValidationGate(),
                        progress),
                jenkinsValidationService,
                new HumanReviewService(executor, claudeConfig, runService, new HumanReviewPromptRenderer()),
                runService,
                progress);

        RemediationSourceReader sourceReader = new RemediationSourceReader(
                ReportDestination.defaultDestination().jsonPath(),
                ReportDestination.remediationPlanDestination().jsonPath());

        GitLabPublicationService publicationService = new GitLabPublicationService(
                repoPath, git, gitLabConfig, new GitLabApiClient(gitLabConfig), runService);

        return new RemediateCommand(scanCommand, planCommand, sourceReader, remediationService,
                runService, reporter, clock, claudeConfig.model(), repoPath, RunIds::generate,
                publicationService);
    }

    /**
     * Assembles the standalone publication step -- deliberately independent of {@link
     * #remediateCommand}: it never touches {@link ClaudeConfig}, {@link JenkinsConfig} or {@link
     * MendGateway}, since it only ever reads a {@code remediate} run's own already-finished artifacts
     * back from disk. {@code gitLabConfigSource} follows the same injectable-{@code Supplier} test seam
     * as every other command's configuration.
     */
    static PublishCommand publishCommand(
            ConsoleReporter reporter,
            Supplier<GitWorktreeConfig> worktreeConfigSource,
            Supplier<GitLabConfig> gitLabConfigSource) {
        Path repoPath = worktreeConfigSource.get().repoPath();
        GitLabConfig gitLabConfig = gitLabConfigSource.get();
        RemediationRunService runService = runService();
        GitLabPublicationService publicationService = new GitLabPublicationService(
                repoPath, new GitCommandRunner(), gitLabConfig, new GitLabApiClient(gitLabConfig), runService);
        return new PublishCommand(publicationService, runService,
                new CohortsIndexJsonReader(), new RemediationSummaryJsonReader(), reporter);
    }

    private static ActionableReportService reportService() {
        return new ActionableReportService(Clock.systemUTC(), ReportDestination.defaultDestination());
    }

    private static RemediationPlanService planService() {
        return new RemediationPlanService(
                Clock.systemUTC(),
                ReportDestination.defaultDestination(),
                ReportDestination.remediationPlanDestination());
    }

    private static RemediationRunService runService() {
        return new RemediationRunService(
                Clock.systemUTC(), Path.of(ReportDestination.DEFAULT_DIRECTORY, "runs"));
    }

    private static PrepareRemediationBranchesCommand branchCommand(
            RemediationRunService runService, ConsoleReporter reporter) {
        RemediationBranchPreparationService branchService = new RemediationBranchPreparationService(
                ReportDestination.remediationPlanDestination().jsonPath(),
                GitWorktreeConfig::fromEnvironment,
                new GitCommandRunner());
        return new PrepareRemediationBranchesCommand(
                branchService, GitWorktreeConfig::fromEnvironment, runService, reporter);
    }

    private static boolean isCommand(String[] args, String command) {
        return args != null && args.length == 1 && command.equals(args[0]);
    }

    /**
     * Recognises {@code remediate} regardless of whether a {@code --dependency} value follows, so a
     * malformed shape (missing value, wrong flag name, extra arguments) still reaches
     * {@link #runRemediate}'s own stricter check and its usual usage-error message, rather than
     * falling through to a different command's dispatch.
     */
    private static boolean isRemediateCommand(String[] args) {
        return args != null && args.length >= 1 && REMEDIATE_COMMAND.equals(args[0]);
    }

    /**
     * Validates the command line and delegates to the scan.
     *
     * <p>The reporter passed in must be one that knows no secrets; {@link ScanCommand} derives a
     * seeded reporter itself once configuration has loaded.
     *
     * <p>A usage error returns before {@link ScanCommand} runs, so an unrecognised command never
     * touches the report directory — the user did not ask for a scan.
     */
    static ExitCode run(String[] args,
                        Supplier<EnvConfig> configSource,
                        MendGateway gateway,
                        ConsoleReporter reporter,
                        ActionableReportService reportService) {
        if (args == null || args.length != 1 || !SCAN_COMMAND.equals(args[0])) {
            reporter.printUsage();
            return ExitCode.USAGE_ERROR;
        }
        return new ScanCommand(configSource, gateway, reporter, reportService).run();
    }

    /** Validates the command line and delegates to {@link RemediationPlanCommand}. */
    static ExitCode runPlanRemediation(String[] args, ConsoleReporter reporter, RemediationPlanService planService) {
        if (args == null || args.length != 1 || !PLAN_REMEDIATION_COMMAND.equals(args[0])) {
            reporter.printUsage();
            return ExitCode.USAGE_ERROR;
        }
        return new RemediationPlanCommand(planService, reporter).run();
    }

    /**
     * Validates the command line and delegates to {@link PrepareRemediationBranchesCommand}.
     * Accepts either {@link #PREPARE_REMEDIATION_BRANCHES_COMMAND} or the deprecated
     * {@link #CREATE_REMEDIATION_WORKTREES_COMMAND} alias -- both dispatch to the same command.
     */
    static ExitCode runPrepareRemediationBranches(
            String[] args, ConsoleReporter reporter, PrepareRemediationBranchesCommand branchCommand) {
        if (args == null || args.length != 1
                || !(PREPARE_REMEDIATION_BRANCHES_COMMAND.equals(args[0])
                        || CREATE_REMEDIATION_WORKTREES_COMMAND.equals(args[0]))) {
            reporter.printUsage();
            return ExitCode.USAGE_ERROR;
        }
        return branchCommand.run();
    }

    /**
     * Validates the command line and delegates to {@link RemediateCommand}. Accepts {@code remediate}
     * (every library in the report), optionally followed by {@code --dependency groupId:artifactId} (a
     * pilot run limited to that one library) and/or a trailing {@code --no-publish} (runs the whole
     * pipeline but never calls {@link com.tungsten.depbot.publication.GitLabPublicationService} --
     * a pilot/debug mode; automatic publication is the default with no flag) -- any other shape,
     * including a missing value after {@code --dependency} or an unrecognised flag name, is a usage error.
     */
    static ExitCode runRemediate(String[] args, ConsoleReporter reporter, RemediateCommand remediateCommand) {
        ParsedRemediateArgs parsed = parseRemediateArgs(args);
        if (parsed == null) {
            reporter.printUsage();
            return ExitCode.USAGE_ERROR;
        }
        return remediateCommand.run(parsed.dependencyFilterRaw(), parsed.noPublish());
    }

    private record ParsedRemediateArgs(String dependencyFilterRaw, boolean noPublish) {
    }

    private static ParsedRemediateArgs parseRemediateArgs(String[] args) {
        if (args == null || args.length < 1 || !REMEDIATE_COMMAND.equals(args[0])) {
            return null;
        }
        return switch (args.length) {
            case 1 -> new ParsedRemediateArgs(null, false);
            case 2 -> NO_PUBLISH_FLAG.equals(args[1])
                    ? new ParsedRemediateArgs(null, true)
                    : null;
            case 3 -> DEPENDENCY_FLAG.equals(args[1]) ? new ParsedRemediateArgs(args[2], false) : null;
            case 4 -> DEPENDENCY_FLAG.equals(args[1]) && NO_PUBLISH_FLAG.equals(args[3])
                    ? new ParsedRemediateArgs(args[2], true)
                    : null;
            default -> null;
        };
    }

    /**
     * Recognises {@code publish} regardless of whether the rest of the line is well-formed, so a
     * malformed shape still reaches {@link #runPublish}'s own stricter check and its usual usage-error
     * message, rather than falling through to a different command's dispatch.
     */
    private static boolean isPublishCommand(String[] args) {
        return args != null && args.length >= 1 && PUBLISH_COMMAND.equals(args[0]);
    }

    /**
     * Validates the command line and delegates to {@link PublishCommand}. Accepts {@code publish --run
     * <run-id>} or {@code publish --run <run-id> --dry-run} -- any other shape is a usage error. There is
     * deliberately no interactive confirmation step anywhere in this path: {@code --dry-run} is the only
     * way to preview what a real publish would do before running it for real.
     */
    static ExitCode runPublish(String[] args, ConsoleReporter reporter, PublishCommand publishCommand) {
        ParsedPublishArgs parsed = parsePublishArgs(args);
        if (parsed == null) {
            reporter.printUsage();
            return ExitCode.USAGE_ERROR;
        }
        return publishCommand.run(parsed.runId(), parsed.dryRun());
    }

    private record ParsedPublishArgs(String runId, boolean dryRun) {
    }

    private static ParsedPublishArgs parsePublishArgs(String[] args) {
        if (args == null || args.length < 3 || !PUBLISH_COMMAND.equals(args[0]) || !RUN_FLAG.equals(args[1])) {
            return null;
        }
        String runId = args[2];
        if (args.length == 3) {
            return new ParsedPublishArgs(runId, false);
        }
        if (args.length == 4 && DRY_RUN_FLAG.equals(args[3])) {
            return new ParsedPublishArgs(runId, true);
        }
        return null;
    }
}
