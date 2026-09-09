package com.tungsten.depbot.cli;

import com.tungsten.depbot.assessment.Assessments;
import com.tungsten.depbot.assessment.BatchAnalysisPromptRenderer;
import com.tungsten.depbot.assessment.BatchAnalysisService;
import com.tungsten.depbot.claude.ClaudeCodeExecutor;
import com.tungsten.depbot.claude.ClaudeConfig;
import com.tungsten.depbot.claude.ClaudePhase;
import com.tungsten.depbot.claude.ClaudeProcessRunner;
import com.tungsten.depbot.claude.FakeClaude;
import com.tungsten.depbot.config.EnvConfig;
import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.git.GitTestRepos;
import com.tungsten.depbot.git.ManagedRepositoryRefresher;
import com.tungsten.depbot.git.RemediationBranchName;
import com.tungsten.depbot.git.RemediationChangeCommitter;
import com.tungsten.depbot.git.RemediationCheckoutManager;
import com.tungsten.depbot.git.RemediationDiffPolicy;
import com.tungsten.depbot.git.RemoteRefsRefresher;
import com.tungsten.depbot.git.SourceRefVerifier;
import com.tungsten.depbot.humanreview.HumanReviewPromptRenderer;
import com.tungsten.depbot.humanreview.HumanReviewService;
import com.tungsten.depbot.implementation.ImplementationPromptRenderer;
import com.tungsten.depbot.implementation.Implementations;
import com.tungsten.depbot.implementation.RemediationImplementationService;
import com.tungsten.depbot.jenkins.FakeJenkinsClient;
import com.tungsten.depbot.jenkins.JenkinsConfig;
import com.tungsten.depbot.jenkins.JenkinsValidationService;
import com.tungsten.depbot.mend.MendGateway;
import com.tungsten.depbot.progress.ConsoleProgressListener;
import com.tungsten.depbot.progress.RemediationProgressListener;
import com.tungsten.depbot.mend.model.MendFix;
import com.tungsten.depbot.mend.model.MendLibrary;
import com.tungsten.depbot.mend.model.VulnerabilityRecord;
import com.tungsten.depbot.mend.model.VulnerabilityReport;
import com.tungsten.depbot.publication.FakeGitLabClient;
import com.tungsten.depbot.publication.GitLabClient;
import com.tungsten.depbot.publication.GitLabConfig;
import com.tungsten.depbot.publication.GitLabPublicationService;
import com.tungsten.depbot.publication.RemoteIdentityVerifier;
import com.tungsten.depbot.publication.VerificationResult;
import com.tungsten.depbot.remediation.RemediationPlanCommand;
import com.tungsten.depbot.remediation.RemediationPlanService;
import com.tungsten.depbot.remediation.RemediationSourceReader;
import com.tungsten.depbot.remediation.VulnerabilityRemediationService;
import com.tungsten.depbot.report.ConsoleReporter;
import com.tungsten.depbot.report.actionable.ActionableReportService;
import com.tungsten.depbot.report.actionable.ReportDestination;
import com.tungsten.depbot.run.RemediationRunService;
import com.tungsten.depbot.validation.FullBuildValidationGate;
import com.tungsten.depbot.validation.RemediationValidationGate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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

/**
 * The pilot command end to end, wired as production wires it: a real Mend response shape, a real git
 * repository, a fake Claude executable answering both phases, and a stub validation gate.
 *
 * <p>What is asserted is that {@code remediate --dependency} really drives the developer-driven flow --
 * two calls, a branch cut from a verified ref, a local commit -- and that everything an operator will want
 * to open afterwards is written where the console says it is.
 */
class RemediateCommandTest {

    private static final EnvConfig CONFIG =
            new EnvConfig("USERKEY-DO-NOT-LEAK-9f3a", "TOKEN-DO-NOT-LEAK-7b1c");
    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-08-10T10:00:00Z"), ZoneOffset.UTC);
    private static final String RUN_ID = "run1";
    private static final String COORDINATES = "org.bouncycastle:bcprov-jdk18on";

    @TempDir
    Path tempDir;

    private final ByteArrayOutputStream outBuffer = new ByteArrayOutputStream();
    private final ByteArrayOutputStream errBuffer = new ByteArrayOutputStream();
    private final ConsoleReporter reporter = new ConsoleReporter(
            new PrintStream(outBuffer, true, StandardCharsets.UTF_8),
            new PrintStream(errBuffer, true, StandardCharsets.UTF_8));

    private final GitCommandRunner git = new GitCommandRunner();
    private Path repo;
    private FakeGitLabClient gitLabClient;

    /**
     * The shared branch name a single automatic group of this batch lands on -- keyed on the verified
     * (ref, sha) pair, so it has to be computed once the repository exists, not hardcoded.
     */
    private String expectedBranch;

    @BeforeEach
    void createRepository() throws Exception {
        repo = GitTestRepos.createOriginAndSingleBranchClone(tempDir, "release/9.2");
        // The single-branch clone has not fetched release/9.2 yet -- that only happens once the command
        // itself refreshes remote refs -- so the verified SHA is read from the bare origin directly.
        String verifiedSha = GitTestRepos.shaOf(tempDir.resolve("origin.git"), "refs/heads/release/9.2");
        expectedBranch = RemediationBranchName.forRun(RUN_ID, "refs/remotes/origin/release/9.2", verifiedSha);
        gitLabClient = new FakeGitLabClient();
    }

    /** Never touches git or GitLab -- this fixture's own origin is a local bare repo, not a real GitLab host. */
    private static final class AlwaysVerifiedIdentityVerifier extends RemoteIdentityVerifier {
        @Override
        public VerificationResult verify(
                GitCommandRunner git, Path repoPath, String remoteName, GitLabClient client, GitLabConfig config) {
            return VerificationResult.success();
        }
    }

    private String out() {
        return outBuffer.toString(StandardCharsets.UTF_8);
    }

    private String err() {
        return errBuffer.toString(StandardCharsets.UTF_8);
    }

    private Path reportDir() {
        return tempDir.resolve("reports");
    }

    private Path runsRoot() {
        return reportDir().resolve("runs");
    }

    /** One critical bcprov finding whose fix text names a forward version, as Mend would report it. */
    private static MendGateway mendReporting() {
        MendLibrary library = new MendLibrary("key-uuid", "bcprov-jdk18on-1.84.jar", "JAVA",
                "the Bouncy Castle provider", "sha1-value", "bcprov-jdk18on", "bcprov-jdk18on", "1.84",
                "org.bouncycastle", "any", "1.8");
        MendFix fix = new MendFix("CVE-2026-58062", "UPGRADE_VERSION", "VENDOR",
                "https://example.invalid/advisory",
                "Upgrade to version org.bouncycastle:bcprov-jdk18on:1.85", "2026-01-01", "upgrade it");
        VulnerabilityRecord record = new VulnerabilityRecord(
                "CVE-2026-58062", "CVE", "critical", "9.8", "High", "9.8",
                "2026-01-01", "2026-02-01", "CVSS:3.1/AV:N/AC:L",
                "https://example.invalid/CVE-2026-58062", "a critical flaw in bcprov",
                "a-project", "a-product", library, fix, List.of(fix), List.of());
        return config -> new VulnerabilityReport(List.of(record));
    }

    /** A fake answering the analysis, then the implementation, editing a POM only in phase two. */
    private FakeClaude bothPhases(String assessmentJson, String implementationJson) throws IOException {
        return FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT,
                        Assessments.claudeOutput(Assessments.answerContaining(assessmentJson)))
                .respondingTo(ClaudePhase.IMPLEMENTATION,
                        Assessments.claudeOutput(Assessments.answerContaining(implementationJson)))
                .respondingTo(ClaudePhase.HUMAN_REVIEW, Assessments.claudeOutput(humanReviewJson()))
                .creatingFile(ClaudePhase.IMPLEMENTATION, "pom.xml", """
                        <project>
                          <dependencies>
                            <dependency>
                              <groupId>org.bouncycastle</groupId>
                              <artifactId>bcprov-jdk18on</artifactId>
                              <version>1.85</version>
                            </dependency>
                          </dependencies>
                        </project>
                        """)
                .build();
    }

    /** A minimal, valid Human Review answer -- used whenever a scenario routes there instead of Implementation. */
    private static String humanReviewJson() {
        return """
                {"schemaVersion":"1.0","coordinates":"org.bouncycastle:bcprov-jdk18on",
                 "vulnerabilitySummary":"a vulnerable bcprov version",
                 "whyVulnerable":"the CVE affects versions before 1.85",
                 "dependencyOrigin":"declared in the root pom",
                 "recommendedChange":"raise the version property to 1.85",
                 "validationApproach":"run dependency:tree and confirm 1.85 resolves"}
                """;
    }

    private RemediateCommand command(FakeClaude fake) {
        return command(fake, Implementations.passingGate());
    }

    private RemediateCommand command(FakeClaude fake, RemediationValidationGate gate) {
        return command(fake, gate, Implementations.passingBuildGate());
    }

    private RemediateCommand command(
            FakeClaude fake, RemediationValidationGate gate, FullBuildValidationGate buildGate) {
        ReportDestination scanDestination = ReportDestination.into(reportDir());
        ReportDestination planDestination = new ReportDestination(reportDir(),
                ReportDestination.REMEDIATION_PLAN_JSON_FILE_NAME,
                ReportDestination.REMEDIATION_PLAN_MARKDOWN_FILE_NAME);

        ScanCommand scanCommand = new ScanCommand(() -> CONFIG, mendReporting(), reporter,
                new ActionableReportService(FIXED_CLOCK, scanDestination));
        RemediationPlanCommand planCommand = new RemediationPlanCommand(
                new RemediationPlanService(FIXED_CLOCK, scanDestination, planDestination), reporter);

        ClaudeConfig claudeConfig =
                new ClaudeConfig(fake.executable().toString(), "opus", 20, Duration.ofSeconds(60));
        RemediationRunService runService = new RemediationRunService(FIXED_CLOCK, runsRoot());
        ClaudeCodeExecutor executor =
                new ClaudeCodeExecutor(claudeConfig, new ClaudeProcessRunner(), runService, FIXED_CLOCK);

        // Wired with the real progress listener, so these tests see what a manual pilot sees.
        RemediationProgressListener progress = new ConsoleProgressListener(reporter, FIXED_CLOCK);
        JenkinsConfig jenkinsConfig = new JenkinsConfig("https://jenkins.example.invalid", "job", "user",
                "token", Duration.ofSeconds(60), Duration.ofMillis(10));
        VulnerabilityRemediationService remediationService = new VulnerabilityRemediationService(
                repo, git, new RemoteRefsRefresher(git),
                new ManagedRepositoryRefresher(git, new SourceRefVerifier(git)),
                new RemediationCheckoutManager(git),
                new SourceRefVerifier(git),
                new BatchAnalysisService(executor, claudeConfig, runService,
                        new BatchAnalysisPromptRenderer()),
                new RemediationImplementationService(executor, claudeConfig, runService,
                        new ImplementationPromptRenderer(), git,
                        new RemediationChangeCommitter(git, new RemediationDiffPolicy()), gate, buildGate,
                        progress),
                new JenkinsValidationService(new FakeJenkinsClient(), jenkinsConfig, git, runService, progress),
                new HumanReviewService(executor, claudeConfig, runService, new HumanReviewPromptRenderer()),
                runService,
                progress);

        GitLabConfig gitLabConfig =
                new GitLabConfig("https://gitlab.example.invalid", "123", "token-not-logged", "origin");
        GitLabPublicationService publicationService = new GitLabPublicationService(
                repo, git, gitLabConfig, gitLabClient, runService, new AlwaysVerifiedIdentityVerifier());

        return new RemediateCommand(scanCommand, planCommand,
                new RemediationSourceReader(scanDestination.jsonPath(), planDestination.jsonPath()),
                remediationService, runService, reporter, FIXED_CLOCK, "opus", repo, () -> RUN_ID,
                publicationService);
    }

    private String summary() throws IOException {
        return Files.readString(
                runsRoot().resolve(RUN_ID).resolve(RemediateCommand.SUMMARY_FILE), StandardCharsets.UTF_8);
    }

    // ---- the pilot ------------------------------------------------------------------------------

    @Test
    @DisplayName("the pilot drives both Claude roles and commits locally on a verified branch")
    void pilotDrivesBothRolesAndCommits() throws Exception {
        FakeClaude fake = bothPhases(Assessments.json(), Implementations.completedJson());

        ExitCode code = command(fake).run(COORDINATES);

        assertEquals(ExitCode.SUCCESS, code, err());
        assertEquals(List.of("assessment", "implementation"), fake.recordedPhaseSequence());
        assertEquals(GitTestRepos.shaOf(repo, "refs/remotes/origin/release/9.2"),
                GitTestRepos.readOutput(repo, "git", "log", "--format=%H", expectedBranch)
                        .lines().skip(1).findFirst().orElseThrow(),
                "the commit must sit directly on the verified commit");
        assertEquals("master", GitTestRepos.currentBranch(repo));
        assertTrue(git.isClean(repo));
    }

    // ---- remediate automatically publishes after a successful pipeline -----------------------------

    @Test
    @DisplayName("a successful pipeline is automatically published to GitLab -- no separate `publish` "
            + "invocation is needed for the ordinary, successful case")
    void successfulPipelineIsAutomaticallyPublished() throws Exception {
        FakeClaude fake = bothPhases(Assessments.json(), Implementations.completedJson());

        ExitCode code = command(fake).run(COORDINATES);

        assertEquals(ExitCode.SUCCESS, code, err());
        assertEquals(1, gitLabClient.mergeRequestCount(),
                "the eligible, fully-validated cohort must have been pushed and a Merge Request opened "
                        + "without any separate publish command");
        assertEquals("release/9.2", gitLabClient.mergeRequestTargetBranch(1));
        assertEquals(GitTestRepos.shaOf(repo, expectedBranch),
                GitTestRepos.shaOf(tempDir.resolve("origin.git"), "refs/heads/" + expectedBranch),
                "the branch pushed to GitLab must be the real, locally-committed one");
        assertTrue(out().contains("Run result: SUCCESS"), out());
        assertTrue(out().contains("Publication result: SUCCESS"), out());
        assertTrue(out().contains("Automatic merge: DISABLED"), out());
    }

    // ---- --no-publish runs the whole pipeline but skips GitLab entirely ---------------------------

    @Test
    @DisplayName("--no-publish runs the full pipeline and commits locally, but never calls GitLab at all")
    void noPublishSkipsGitLabEntirely() throws Exception {
        FakeClaude fake = bothPhases(Assessments.json(), Implementations.completedJson());

        ExitCode code = command(fake).run(COORDINATES, true);

        assertEquals(ExitCode.SUCCESS, code, err());
        assertEquals(0, gitLabClient.callCount(),
                "no GitLab mutation of any kind -- push, branch publication, MR, Issue or comment -- "
                        + "may happen under --no-publish");
        assertEquals(List.of("assessment", "implementation"), fake.recordedPhaseSequence());
        assertEquals(GitTestRepos.shaOf(repo, "refs/remotes/origin/release/9.2"),
                GitTestRepos.readOutput(repo, "git", "log", "--format=%H", expectedBranch)
                        .lines().skip(1).findFirst().orElseThrow(),
                "the pipeline itself is unaffected: the commit still sits directly on the verified commit");
        assertTrue(out().contains("Publication: SKIPPED (--no-publish)"), out());
        assertTrue(out().contains("Run result: SUCCESS"), out());
        assertTrue(out().contains("Publication result: SKIPPED (--no-publish)"), out());
    }

    @Test
    @DisplayName("a publication failure never touches the remediation run's own artifacts, and the run "
            + "remains fully retryable through the exact same publication service afterward")
    void publicationFailurePreservesTheRunForRetry() throws Exception {
        FakeClaude fake = bothPhases(Assessments.json(), Implementations.completedJson());
        gitLabClient.failOnCallNumber(1, new com.tungsten.depbot.publication.GitLabPublicationException(
                "simulated network failure"));

        ExitCode code = command(fake).run(COORDINATES);

        assertEquals(ExitCode.PUBLICATION_FAILED, code,
                "a publication failure must be reported distinctly, never as a remediation failure");
        assertTrue(err().contains("could not") || out().contains("PUBLICATION_FAILED")
                        || out().contains("Publication result: PUBLICATION_FAILED"),
                "the publication failure must be visible: out=" + out() + " err=" + err());
        // The remediation artifacts are completely untouched by the publication failure.
        assertTrue(Files.exists(runsRoot().resolve(RUN_ID).resolve(RemediateCommand.SUMMARY_FILE)));
        assertTrue(Files.exists(runsRoot().resolve(RUN_ID).resolve(
                com.tungsten.depbot.remediation.CohortsIndexJsonReader.FILE_NAME)));
        assertEquals(GitTestRepos.shaOf(repo, "refs/remotes/origin/release/9.2"),
                GitTestRepos.readOutput(repo, "git", "log", "--format=%H", expectedBranch)
                        .lines().skip(1).findFirst().orElseThrow(),
                "the local commit itself is completely unaffected by the publication failure");

        // A later, independent retry through the exact same publication service now succeeds -- proving
        // the run is genuinely retryable, exactly as `publish --run <run-id>` would do it.
        com.tungsten.depbot.remediation.CohortsIndex cohortsIndex = new com.tungsten.depbot.remediation.CohortsIndexJsonReader()
                .read(runsRoot().resolve(RUN_ID).resolve(com.tungsten.depbot.remediation.CohortsIndexJsonReader.FILE_NAME));
        com.tungsten.depbot.remediation.RemediationSummary summary = new com.tungsten.depbot.remediation.RemediationSummaryJsonReader()
                .read(runsRoot().resolve(RUN_ID).resolve(RemediateCommand.SUMMARY_FILE));
        GitLabConfig retryConfig =
                new GitLabConfig("https://gitlab.example.invalid", "123", "token-not-logged", "origin");
        com.tungsten.depbot.run.RemediationRunService retryRunService =
                new com.tungsten.depbot.run.RemediationRunService(FIXED_CLOCK, runsRoot());
        GitLabPublicationService retryService = new GitLabPublicationService(
                repo, git, retryConfig, gitLabClient, retryRunService, new AlwaysVerifiedIdentityVerifier());

        var retriedIndex = retryService.publish(RUN_ID, cohortsIndex, summary);

        assertEquals(1, gitLabClient.mergeRequestCount(), "the retry succeeds and opens exactly one Merge Request");
        assertEquals(com.tungsten.depbot.remediation.RemediationCohort.PublicationStatus.MERGE_REQUEST_OPENED,
                retriedIndex.cohorts().get(0).status());
    }

    @Test
    @DisplayName("a cohort whose full build failed is never eligible, so it is never published -- publish "
            + "must not create a Merge Request for a commit that did not pass every gate")
    void ineligibleCohortIsNeverPublished() throws Exception {
        FakeClaude fake = bothPhases(Assessments.json(), Implementations.completedJson());

        ExitCode code = command(fake, Implementations.passingGate(),
                Implementations.failingBuildGate("tests failed in module x")).run(COORDINATES);

        assertEquals(ExitCode.MANUAL_REMEDIATION_REQUIRED, code, err());
        assertEquals(0, gitLabClient.mergeRequestCount(),
                "a commit whose full build failed must never be published, even though it was committed locally");
    }

    @Test
    @DisplayName("every step is announced live, in order, with what it produced")
    void everyStepIsAnnouncedLive() throws Exception {
        FakeClaude fake = bothPhases(Assessments.json(), Implementations.completedJson());

        command(fake).run(COORDINATES);

        String out = out();
        assertTrue(out.contains("Run ID: " + RUN_ID), out);
        assertTrue(out.contains("refreshing remote refs"), out);
        assertTrue(out.contains("vulnerability analysis: read-only"), out);
        assertTrue(out.contains("vulnerability analysis done in"), out);
        assertTrue(out.contains("1 findings, 1 requiring remediation, 1 group(s)"), out);
        assertTrue(out.contains("verifying the source ref"), out);
        assertTrue(out.contains("refs/remotes/origin/release/9.2 is "), out);
        assertTrue(out.contains("preparing the remediation branch: " + expectedBranch), out);
        assertTrue(out.contains("implementation done in"), out);
        assertTrue(out.contains("local validation done in"), out);
        assertTrue(out.contains("commit or roll back done in"), out);
        assertTrue(out.contains("COMMITTED_PENDING_VALIDATION"), out);
        assertTrue(out.contains("full build validation: running mvn -B clean package"), out);
        assertTrue(out.contains("full build validation done in"), out);
        assertTrue(out.contains("restoring the checkout done in"), out);
        assertTrue(out.contains("back where it started"), out);

        assertTrue(indexOfOrFail(out, "vulnerability analysis done in")
                        < indexOfOrFail(out, "preparing the remediation branch"),
                "the branch must be announced only after the analysis produced a ref: " + out);
        assertTrue(indexOfOrFail(out, "commit or roll back done in")
                        < indexOfOrFail(out, "full build validation: running mvn -B clean package"),
                "the full build must only run after the commit decision: " + out);
        assertTrue(indexOfOrFail(out, "full build validation done in")
                        < indexOfOrFail(out, "restoring the checkout"),
                "the full build must finish before the checkout is restored: " + out);
    }

    private static int indexOfOrFail(String text, String needle) {
        int index = text.indexOf(needle);
        assertTrue(index >= 0, "expected to find \"" + needle + "\" in: " + text);
        return index;
    }

    @Test
    @DisplayName("the run ends by naming the counts and where to look")
    void runEndsByNamingWhereToLook() throws Exception {
        FakeClaude fake = bothPhases(Assessments.json(), Implementations.completedJson());

        command(fake).run(COORDINATES);

        String out = out();
        assertTrue(out.contains("Libraries remediated: 1"), out);
        assertTrue(out.contains("Automatic remediation groups: 1"), out);
        assertTrue(out.contains("Commits: 1"), out);
        assertTrue(out.contains("Fully validated (committed and built successfully): 1"), out);
        assertTrue(out.contains("Build validation failed (commit kept for diagnosis): 0"), out);
        assertTrue(out.contains("Run summary: "), out);
        assertTrue(out.contains("Run artifacts: "), out);
        assertTrue(out.contains("a full `mvn -B clean package` was run on every committed change"), out);
    }

    @Test
    @DisplayName("every artifact the summary points at actually exists on disk")
    void everyArtifactExists() throws Exception {
        FakeClaude fake = bothPhases(Assessments.json(), Implementations.completedJson());

        command(fake).run(COORDINATES);

        Path analysis = runsRoot().resolve(RUN_ID).resolve("analysis").resolve("attempt-1");
        assertTrue(Files.exists(analysis.resolve("prompt.md")));
        assertTrue(Files.exists(analysis.resolve("analysis.json")));
        assertTrue(Files.exists(analysis.resolve("stdout.json")));

        Path unit = runsRoot().resolve(RUN_ID).resolve("units")
                .resolve("critical__org.bouncycastle__bcprov-jdk18on");
        Path attempt = unit.resolve("implementation").resolve("attempt-1");
        assertTrue(Files.exists(attempt.resolve("prompt.md")));
        assertTrue(Files.exists(attempt.resolve("implementation-report.json")));
        assertTrue(Files.exists(attempt.resolve("remediation-report.json")),
                "the strict, per-commit report must exist alongside the free-form implementation report");
        assertTrue(Files.exists(attempt.resolve("patch.diff")));
        assertTrue(Files.exists(attempt.resolve("validation.json")));
        assertTrue(Files.exists(attempt.resolve("validation-output.txt")));
        assertTrue(Files.exists(attempt.resolve("full-build-validation.json")));
        assertTrue(Files.exists(attempt.resolve("full-build-output.txt")));
        assertTrue(Files.readString(attempt.resolve("patch.diff")).contains("1.85"));
    }

    @Test
    @DisplayName("the summary records the ref, the commit git resolved, and the local commit")
    void summaryRecordsTheChain() throws Exception {
        FakeClaude fake = bothPhases(Assessments.json(), Implementations.completedJson());

        command(fake).run(COORDINATES);

        String summary = summary();
        assertTrue(summary.contains("\"coordinates\" : \"" + COORDINATES + "\""), summary);
        assertTrue(summary.contains("\"sourceRefResolved\" : \"refs/remotes/origin/release/9.2\""), summary);
        assertTrue(summary.contains(GitTestRepos.shaOf(repo, "refs/remotes/origin/release/9.2")), summary);
        assertTrue(summary.contains("\"branchName\" : \"" + expectedBranch + "\""), summary);
        assertTrue(summary.contains("\"changeDisposition\" : \"COMMITTED_PENDING_VALIDATION\""), summary);
        assertTrue(summary.contains("\"validationStatus\" : \"PASSED\""), summary);
        assertTrue(summary.contains("\"fullBuildValidationStatus\" : \"PASSED\""), summary);
        assertTrue(summary.contains("\"fullBuildLogPath\""), summary);
        assertTrue(summary.contains("\"claimedShaMatchedGit\" : false"),
                "the model's SHA claim and git's answer are both on the record: " + summary);
        assertTrue(summary.contains("\"dependencyFilter\" : \"" + COORDINATES + "\""), summary);
    }

    @Test
    @DisplayName("credentials never reach the console or the run summary")
    void credentialsNeverReachTheOutput() throws Exception {
        FakeClaude fake = bothPhases(Assessments.json(), Implementations.completedJson());

        command(fake).run(COORDINATES);

        for (String secret : List.of(CONFIG.userKey(), CONFIG.projectToken())) {
            assertFalse(out().contains(secret), "credential on stdout");
            assertFalse(err().contains(secret), "credential on stderr");
            assertFalse(summary().contains(secret), "credential in the run summary");
        }
    }

    // ---- the gates stop the pilot without changing anything ---------------------------------------

    @Test
    @DisplayName("a high impact score alone never blocks automatic remediation -- only automationSafety does")
    void highImpactScoreAloneDoesNotBlockAutomaticRemediation() throws Exception {
        FakeClaude fake = bothPhases(
                Assessments.json().replace("\"impactScore\": 2", "\"impactScore\": 9"),
                Implementations.completedJson());

        ExitCode code = command(fake).run(COORDINATES);

        assertEquals(ExitCode.SUCCESS, code, err());
        assertTrue(GitTestRepos.readOutput(repo, "git", "log", "--format=%H", expectedBranch)
                        .lines().count() >= 2,
                "a high impact score judged AUTOMATIC_ALLOWED must still be committed: " + err());
    }

    @Test
    @DisplayName("legacy automationSafety AUTOMATION_BLOCKED is now treated identically to "
            + "HUMAN_REVIEW_REQUIRED -- genuinely attempted through the risky singleton path, never "
            + "hard-stopped")
    void automationBlockedIsNowAttemptedLikeHumanReviewRequired() throws Exception {
        FakeClaude fake = bothPhases(
                Assessments.json().replace(
                        "\"automationSafety\": \"AUTOMATIC_ALLOWED\"",
                        "\"automationSafety\": \"AUTOMATION_BLOCKED\""),
                Implementations.blockedJson());

        ExitCode code = command(fake).run(COORDINATES);

        assertEquals(ExitCode.HUMAN_REVIEW_REQUIRED, code,
                "an attempted-but-incomplete legacy AUTOMATION_BLOCKED group must exit like "
                        + "HUMAN_REVIEW_REQUIRED, never like a genuine hard stop");
        assertTrue(fake.recordedPhaseSequence().contains("implementation"),
                "a legacy AUTOMATION_BLOCKED group must genuinely be attempted, never skipped: "
                        + fake.recordedPhaseSequence());
        assertEquals("human-review", fake.recordedPhaseSequence().get(fake.recordedPhaseSequence().size() - 1));
        assertFalse(git.listRefs(repo).contains(expectedBranch));
        assertTrue(out().contains("Needs human review (Human Review Report prepared, no automatic change made): 1"),
                out());
    }

    @Test
    @DisplayName("automationSafety HUMAN_REVIEW_REQUIRED is genuinely attempted through the Remediation "
            + "Engineer -- but a risky attempt that could not be completed still ends up needing a human, "
            + "exiting its own distinct code")
    void humanReviewRequiredIsAttemptedButStillNeedsAHumanWhenItCannotBeCompleted() throws Exception {
        // Deliberately STOPPED_BLOCKED (not completedJson()): a HUMAN_REVIEW_REQUIRED group is not
        // skipped -- Implementation genuinely runs (see the phase-sequence assertion below). A group
        // whose attempt succeeds is published as its own isolated, human-review-only MR instead (see
        // RiskyGroupRemediationTest at the service level); this test covers the other, still-common
        // outcome -- an honest self-reported "I cannot safely complete this" -- which is exactly what
        // still must exit distinguishably from a genuine analysis-incomplete/no-plan-possible hard stop.
        FakeClaude fake = bothPhases(
                Assessments.json().replace(
                        "\"automationSafety\": \"AUTOMATIC_ALLOWED\"",
                        "\"automationSafety\": \"HUMAN_REVIEW_REQUIRED\""),
                Implementations.blockedJson());

        ExitCode code = command(fake).run(COORDINATES);

        assertEquals(ExitCode.HUMAN_REVIEW_REQUIRED, code,
                "a prepared Human Review Report must not exit like a real failure");
        assertNotEquals(ExitCode.MANUAL_REMEDIATION_REQUIRED, code,
                "the whole point is that these two must be distinguishable at the process boundary");
        assertTrue(fake.recordedPhaseSequence().contains("implementation"),
                "a HUMAN_REVIEW_REQUIRED group must genuinely be attempted, not skipped: "
                        + fake.recordedPhaseSequence());
        assertEquals("human-review", fake.recordedPhaseSequence().get(fake.recordedPhaseSequence().size() - 1),
                "an attempt that could not be completed must still end at Human Review: "
                        + fake.recordedPhaseSequence());
        assertTrue(git.listRefs(repo).lines().noneMatch(ref -> ref.contains("remediation/")),
                "no remediation branch of any kind (ordinary or risky) may survive a failed attempt");
        assertTrue(git.isClean(repo));
        // Printed to stderr only, like printRemediationStopped/printBuildValidationFailed -- it must
        // survive piping stdout elsewhere. The stdout summary still counts it, just under a capitalised
        // "Needs human review" heading, not this exact per-item phrase.
        assertTrue(err().contains("needs human review"), err());
        assertTrue(summary().contains("\"automationSafety\" : \"HUMAN_REVIEW_REQUIRED\""), summary());
    }

    @Test
    @DisplayName("a well-evidenced no-action answer exits zero, with nothing changed")
    void noActionRequiredExitsZero() throws Exception {
        String noAction = """
                {"schemaVersion":"1.0","findings":[
                  {"coordinates":"org.bouncycastle:bcprov-jdk18on",
                   "summary":"already fixed on every ref","conclusion":"NO_ACTION_REQUIRED",
                   "evidence":["no ref declares a vulnerable version"],
                   "noActionBasis":"ALREADY_AT_OR_ABOVE_FIXED_VERSION"}
                ],"remediationGroups":[]}
                """;
        FakeClaude fake = bothPhases(noAction, Implementations.completedJson());

        ExitCode code = command(fake).run(COORDINATES);

        assertEquals(ExitCode.SUCCESS, code, err());
        assertEquals(1, fake.invocationCount());
        assertTrue(out().contains("Nothing to remediate: 1"), out());
        assertFalse(git.listRefs(repo).contains(expectedBranch));
    }

    @Test
    @DisplayName("a refused local validation leaves no commit and exits MANUAL_REMEDIATION_REQUIRED")
    void refusedValidationLeavesNoCommit() throws Exception {
        FakeClaude fake = bothPhases(Assessments.json(), Implementations.completedJson());

        ExitCode code = command(fake, Implementations.failingGate("bcprov still resolves to 1.84"))
                .run(COORDINATES);

        assertEquals(ExitCode.MANUAL_REMEDIATION_REQUIRED, code);
        assertTrue(out().contains("local validation done in"), out());
        assertTrue(out().contains("FAILED"), out());
        assertTrue(err().contains("still resolves to 1.84"), err());
        assertFalse(git.listRefs(repo).contains(expectedBranch),
                "with the cohort's only group never reaching a Jenkins-validated commit, the shared "
                        + "branch is never even created -- isolation happens on a throwaway branch that "
                        + "is cleaned up, not on this one");
        assertTrue(git.isClean(repo));
        assertTrue(summary().contains("\"validationStatus\" : \"FAILED\""), summary());
    }

    @Test
    @DisplayName("a failed refresh stops the pilot before Claude is called at all")
    void failedRefreshStopsBeforeClaude() throws Exception {
        GitTestRepos.run(repo, "git", "remote", "set-url", "origin",
                tempDir.resolve("gone.git").toString());
        FakeClaude fake = bothPhases(Assessments.json(), Implementations.completedJson());

        ExitCode code = command(fake).run(COORDINATES);

        assertEquals(ExitCode.MANUAL_REMEDIATION_REQUIRED, code);
        assertEquals(0, fake.invocationCount(), "no Claude call may run against stale refs");
        assertTrue(out().contains("refreshing remote refs done in"), out());
        assertTrue(out().contains("failed"), out());
        assertTrue(err().contains("REMOTE_REFS_REFRESH"), err());
        assertTrue(err().contains("may be out of date"), err());
        assertFalse(git.listRefs(repo).contains(expectedBranch));
    }

    // ---- argument handling -------------------------------------------------------------------------

    @Test
    @DisplayName("a malformed --dependency value fails before anything is scanned")
    void malformedFilterFailsBeforeScanning() throws Exception {
        FakeClaude fake = bothPhases(Assessments.json(), Implementations.completedJson());

        ExitCode code = command(fake).run("not-coordinates");

        assertEquals(ExitCode.USAGE_ERROR, code);
        assertEquals(0, fake.invocationCount());
        assertFalse(Files.exists(reportDir().resolve(ReportDestination.DEFAULT_JSON_FILE_NAME)),
                "a usage error must not have produced a scan report");
    }

    @Test
    @DisplayName("a dependency the report does not contain is a source error, not a silent no-op")
    void unknownDependencyIsASourceError() throws Exception {
        FakeClaude fake = bothPhases(Assessments.json(), Implementations.completedJson());

        ExitCode code = command(fake).run("com.example:not-in-the-report");

        assertEquals(ExitCode.REMEDIATION_SOURCE_ERROR, code);
        assertEquals(0, fake.invocationCount());
        assertTrue(err().contains("com.example:not-in-the-report"), err());
    }

    @Test
    @DisplayName("bare remediate works through the whole report rather than needing a filter")
    void bareRemediateWorksThroughTheReport() throws Exception {
        FakeClaude fake = bothPhases(Assessments.json(), Implementations.completedJson());

        ExitCode code = command(fake).run();

        assertEquals(ExitCode.SUCCESS, code, err());
        assertTrue(summary().contains("\"dependencyFilter\" : null"), summary());
        assertTrue(out().contains("Remediating 1 library/libraries"), out());
    }
}
