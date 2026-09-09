package com.tungsten.depbot;

import com.tungsten.depbot.claude.ClaudeCodeExecutor;
import com.tungsten.depbot.claude.ClaudeConfig;
import com.tungsten.depbot.claude.ClaudeProcessRunner;
import com.tungsten.depbot.cli.ExitCode;
import com.tungsten.depbot.cli.PrepareRemediationBranchesCommand;
import com.tungsten.depbot.cli.RemediateCommand;
import com.tungsten.depbot.cli.ScanCommand;
import com.tungsten.depbot.config.EnvConfig;
import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.git.GitWorktreeConfig;
import com.tungsten.depbot.git.ManagedRepositoryRefresher;
import com.tungsten.depbot.git.RemediationBranchPreparationService;
import com.tungsten.depbot.git.RemediationChangeCommitter;
import com.tungsten.depbot.git.RemediationCheckoutManager;
import com.tungsten.depbot.git.RemediationDiffPolicy;
import com.tungsten.depbot.git.RemoteRefsRefresher;
import com.tungsten.depbot.git.SourceRefVerifier;
import com.tungsten.depbot.jenkins.FakeJenkinsClient;
import com.tungsten.depbot.jenkins.JenkinsConfig;
import com.tungsten.depbot.jenkins.JenkinsValidationService;
import com.tungsten.depbot.mend.MendGateway;
import com.tungsten.depbot.mend.model.VulnerabilityReport;
import com.tungsten.depbot.publication.FakeGitLabClient;
import com.tungsten.depbot.publication.GitLabConfig;
import com.tungsten.depbot.publication.GitLabPublicationService;
import com.tungsten.depbot.assessment.BatchAnalysisPromptRenderer;
import com.tungsten.depbot.assessment.BatchAnalysisService;
import com.tungsten.depbot.humanreview.HumanReviewPromptRenderer;
import com.tungsten.depbot.humanreview.HumanReviewService;
import com.tungsten.depbot.implementation.ImplementationPromptRenderer;
import com.tungsten.depbot.implementation.Implementations;
import com.tungsten.depbot.implementation.RemediationImplementationService;
import com.tungsten.depbot.remediation.RemediationPlanCommand;
import com.tungsten.depbot.remediation.RemediationPlanService;
import com.tungsten.depbot.remediation.RemediationSourceReader;
import com.tungsten.depbot.remediation.VulnerabilityRemediationService;
import com.tungsten.depbot.report.actionable.ActionableReportService;
import com.tungsten.depbot.report.actionable.ReportDestination;
import com.tungsten.depbot.run.RemediationRunService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MainCliTest {

    private static final EnvConfig CONFIG =
            new EnvConfig("USERKEY-DO-NOT-LEAK-9f3a", "TOKEN-DO-NOT-LEAK-7b1c");

    private static final MendGateway EMPTY_REPORT =
            config -> new VulnerabilityReport(List.of());

    /** Reports are written into a temporary directory, never the real one. */
    @TempDir
    Path reportDir;

    private ActionableReportService reportService() {
        return new ActionableReportService(
                Clock.fixed(Instant.parse("2026-01-02T03:04:05Z"), ZoneOffset.UTC),
                ReportDestination.into(reportDir));
    }

    private ExitCode runWith(CapturedConsole console, String... args) {
        return Main.run(args, () -> CONFIG, EMPTY_REPORT, console.reporter(), reportService());
    }

    private RemediationPlanService planService() {
        return new RemediationPlanService(
                Clock.fixed(Instant.parse("2026-01-02T03:04:05Z"), ZoneOffset.UTC),
                ReportDestination.into(reportDir),
                new ReportDestination(reportDir,
                        ReportDestination.REMEDIATION_PLAN_JSON_FILE_NAME,
                        ReportDestination.REMEDIATION_PLAN_MARKDOWN_FILE_NAME));
    }

    private ExitCode runPlanRemediationWith(CapturedConsole console, String... args) {
        return Main.runPlanRemediation(args, console.reporter(), planService());
    }

    private RemediationBranchPreparationService branchService() {
        return new RemediationBranchPreparationService(
                reportDir.resolve(ReportDestination.REMEDIATION_PLAN_JSON_FILE_NAME),
                () -> {
                    throw new AssertionError("config must not be read when the plan report is missing");
                },
                new GitCommandRunner());
    }

    private RemediationRunService runService() {
        return new RemediationRunService(
                Clock.fixed(Instant.parse("2026-01-02T03:04:05Z"), ZoneOffset.UTC), reportDir.resolve("runs"));
    }

    private PrepareRemediationBranchesCommand branchCommand(CapturedConsole console) {
        return new PrepareRemediationBranchesCommand(
                branchService(),
                () -> {
                    throw new AssertionError("config must not be read when the plan report is missing");
                },
                runService(), console.reporter());
    }

    private ExitCode runPrepareRemediationBranchesWith(CapturedConsole console, String... args) {
        return Main.runPrepareRemediationBranches(args, console.reporter(), branchCommand(console));
    }

    /**
     * Wired exactly as production wires it, except that the Claude executable does not exist and the
     * repository is a temporary directory. These tests only exercise argument dispatch, which returns
     * before any stage runs.
     */
    private RemediateCommand remediateCommand(CapturedConsole console) {
        ScanCommand scanCommand = new ScanCommand(() -> CONFIG, EMPTY_REPORT, console.reporter(), reportService());
        RemediationPlanCommand planCommand = new RemediationPlanCommand(planService(), console.reporter());

        GitCommandRunner git = new GitCommandRunner();
        ClaudeConfig claudeConfig = new ClaudeConfig(
                reportDir.resolve("no-claude-here").toString(), "opus", 5, Duration.ofSeconds(30));
        Clock fixedClock = Clock.fixed(Instant.parse("2026-01-02T03:04:05Z"), ZoneOffset.UTC);
        ClaudeCodeExecutor executor =
                new ClaudeCodeExecutor(claudeConfig, new ClaudeProcessRunner(), runService(), fixedClock);

        JenkinsConfig jenkinsConfig = new JenkinsConfig("https://jenkins.example.invalid", "job", "user",
                "token", Duration.ofSeconds(60), Duration.ofMillis(10));
        VulnerabilityRemediationService remediationService = new VulnerabilityRemediationService(
                reportDir, git, new RemoteRefsRefresher(git),
                new ManagedRepositoryRefresher(git, new SourceRefVerifier(git)),
                new RemediationCheckoutManager(git),
                new SourceRefVerifier(git),
                new BatchAnalysisService(executor, claudeConfig, runService(),
                        new BatchAnalysisPromptRenderer()),
                new RemediationImplementationService(executor, claudeConfig, runService(),
                        new ImplementationPromptRenderer(), git,
                        new RemediationChangeCommitter(git, new RemediationDiffPolicy()),
                        Implementations.passingGate(), Implementations.passingBuildGate()),
                new JenkinsValidationService(new FakeJenkinsClient(), jenkinsConfig, git, runService()),
                new HumanReviewService(executor, claudeConfig, runService(), new HumanReviewPromptRenderer()),
                runService());

        RemediationSourceReader sourceReader = new RemediationSourceReader(
                reportDir.resolve(ReportDestination.DEFAULT_JSON_FILE_NAME),
                reportDir.resolve(ReportDestination.REMEDIATION_PLAN_JSON_FILE_NAME));

        GitLabConfig gitLabConfig =
                new GitLabConfig("https://gitlab.example.invalid", "123", "unused-token", "origin");
        GitLabPublicationService publicationService = new GitLabPublicationService(
                reportDir, git, gitLabConfig, new FakeGitLabClient(), runService());

        return new RemediateCommand(scanCommand, planCommand, sourceReader, remediationService,
                runService(), console.reporter(), fixedClock, "opus", reportDir, () -> "run1",
                publicationService);
    }

    private ExitCode runRemediateWith(CapturedConsole console, String... args) {
        return Main.runRemediate(args, console.reporter(), remediateCommand(console));
    }

    @Test
    @DisplayName("scan reaches the scan path and succeeds")
    void scanRunsTheCheck() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.SUCCESS, runWith(console, "scan"));
        assertTrue(console.out().contains("Mend vulnerability check completed"));
    }

    @Test
    @DisplayName("no argument prints usage to stderr and returns USAGE_ERROR")
    void noArgument() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR, runWith(console));

        assertTrue(console.err().contains("Usage: java -jar dependency-maintenance-bot.jar "
                + "<remediate|scan|plan-remediation|prepare-remediation-branches"));
        assertEquals("", console.out());
    }

    @Test
    @DisplayName("an unknown argument prints usage and returns USAGE_ERROR")
    void unknownArgument() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR, runWith(console, "bogus"));
        assertTrue(console.err().contains("Usage:"));
    }

    @Test
    @DisplayName("extra arguments after scan are rejected")
    void extraArguments() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR, runWith(console, "scan", "extra"));
        assertFalse(console.out().contains("Mend vulnerability check completed"));
    }

    @Test
    @DisplayName("command matching is exact and case-sensitive")
    void commandMatchingIsExact() {
        assertEquals(ExitCode.USAGE_ERROR, runWith(new CapturedConsole(), "SCAN"));
        assertEquals(ExitCode.USAGE_ERROR, runWith(new CapturedConsole(), "Scan"));
        assertEquals(ExitCode.USAGE_ERROR, runWith(new CapturedConsole(), " scan"));
    }

    @Test
    @DisplayName("a null argument array is treated as a usage error")
    void nullArguments() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR,
                Main.run(null, () -> CONFIG, EMPTY_REPORT, console.reporter(), reportService()));
    }

    @Test
    @DisplayName("exit codes have the documented numeric values")
    void exitCodeValues() {
        assertEquals(0, ExitCode.SUCCESS.value());
        assertEquals(1, ExitCode.USAGE_ERROR.value());
        assertEquals(2, ExitCode.CONFIG_ERROR.value());
        assertEquals(3, ExitCode.API_ERROR.value());
        assertEquals(4, ExitCode.NETWORK_ERROR.value());
        assertEquals(5, ExitCode.MALFORMED_RESPONSE.value());
        assertEquals(6, ExitCode.REPORT_WRITE_ERROR.value());
        assertEquals(7, ExitCode.REMEDIATION_SOURCE_ERROR.value());
        assertEquals(8, ExitCode.GIT_OPERATION_ERROR.value());
        assertEquals(9, ExitCode.REMEDIATION_EXECUTION_ERROR.value());
        assertEquals(70, ExitCode.UNEXPECTED_ERROR.value());
    }

    @Test
    @DisplayName("plan-remediation with no source report returns REMEDIATION_SOURCE_ERROR")
    void planRemediationWithoutSourceReport() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.REMEDIATION_SOURCE_ERROR, runPlanRemediationWith(console, "plan-remediation"));
        assertTrue(console.err().contains("Remediation plan error:"));
    }

    @Test
    @DisplayName("plan-remediation with an unknown argument prints usage and returns USAGE_ERROR")
    void planRemediationUnknownArgument() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR, runPlanRemediationWith(console, "bogus"));
        assertTrue(console.err().contains("Usage:"));
    }

    @Test
    @DisplayName("extra arguments after plan-remediation are rejected")
    void planRemediationExtraArguments() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR, runPlanRemediationWith(console, "plan-remediation", "extra"));
    }

    @Test
    @DisplayName("a null argument array is a usage error for plan-remediation too")
    void planRemediationNullArguments() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR, Main.runPlanRemediation(null, console.reporter(), planService()));
    }

    @Test
    @DisplayName("prepare-remediation-branches with no remediation plan returns REMEDIATION_SOURCE_ERROR")
    void prepareRemediationBranchesWithoutPlan() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.REMEDIATION_SOURCE_ERROR,
                runPrepareRemediationBranchesWith(console, "prepare-remediation-branches"));
        assertTrue(console.err().contains("Remediation plan error:"));
    }

    @Test
    @DisplayName("the deprecated create-remediation-worktrees alias dispatches to the same command")
    void deprecatedAliasDispatchesToTheSameCommand() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.REMEDIATION_SOURCE_ERROR,
                runPrepareRemediationBranchesWith(console, "create-remediation-worktrees"));
        assertTrue(console.err().contains("Remediation plan error:"));
    }

    @Test
    @DisplayName("prepare-remediation-branches with an unknown argument prints usage and returns USAGE_ERROR")
    void prepareRemediationBranchesUnknownArgument() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR, runPrepareRemediationBranchesWith(console, "bogus"));
        assertTrue(console.err().contains("Usage:"));
    }

    @Test
    @DisplayName("extra arguments after prepare-remediation-branches are rejected")
    void prepareRemediationBranchesExtraArguments() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR,
                runPrepareRemediationBranchesWith(console, "prepare-remediation-branches", "extra"));
    }

    @Test
    @DisplayName("a null argument array is a usage error for prepare-remediation-branches too")
    void prepareRemediationBranchesNullArguments() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR,
                Main.runPrepareRemediationBranches(null, console.reporter(), branchCommand(console)));
    }

    @Test
    @DisplayName("remediate with an unknown argument prints usage and returns USAGE_ERROR")
    void remediateUnknownArgument() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR, runRemediateWith(console, "bogus"));
        assertTrue(console.err().contains("Usage:"));
    }

    @Test
    @DisplayName("extra arguments after remediate are rejected")
    void remediateExtraArguments() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR, runRemediateWith(console, "remediate", "extra"));
    }

    @Test
    @DisplayName("a null argument array is a usage error for remediate too")
    void remediateNullArguments() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR, Main.runRemediate(null, console.reporter(), remediateCommand(console)));
    }

    @Test
    @DisplayName("remediate --no-publish alone is a valid, recognised shape")
    void remediateNoPublishAloneIsValid() {
        CapturedConsole console = new CapturedConsole();
        assertNotEquals(ExitCode.USAGE_ERROR, runRemediateWith(console, "remediate", "--no-publish"));
    }

    @Test
    @DisplayName("remediate --dependency groupId:artifactId --no-publish is a valid, recognised shape")
    void remediateDependencyThenNoPublishIsValid() {
        CapturedConsole console = new CapturedConsole();
        assertNotEquals(ExitCode.USAGE_ERROR, runRemediateWith(
                console, "remediate", "--dependency", "com.example:artifact", "--no-publish"));
    }

    @Test
    @DisplayName("--no-publish before --dependency is not a recognised shape")
    void remediateNoPublishBeforeDependencyIsRejected() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR, runRemediateWith(
                console, "remediate", "--no-publish", "--dependency", "com.example:artifact"));
    }

    @Test
    @DisplayName("a misspelled --no-publish flag is a usage error")
    void remediateMisspelledNoPublishIsRejected() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR, runRemediateWith(console, "remediate", "--nopublish"));
    }
}
