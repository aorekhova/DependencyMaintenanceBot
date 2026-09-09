package com.tungsten.depbot.remediation;

import com.tungsten.depbot.assessment.Assessments;
import com.tungsten.depbot.assessment.BatchAnalysisService;
import com.tungsten.depbot.assessment.BatchAnalysisPromptRenderer;
import com.tungsten.depbot.assessment.VulnerabilityWorkItem;
import com.tungsten.depbot.claude.ClaudeCodeExecutor;
import com.tungsten.depbot.claude.ClaudeConfig;
import com.tungsten.depbot.claude.ClaudePhase;
import com.tungsten.depbot.claude.ClaudeProcessRunner;
import com.tungsten.depbot.claude.FakeClaude;
import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.git.GitTestRepos;
import com.tungsten.depbot.git.ManagedRepositoryRefresher;
import com.tungsten.depbot.git.RemediationBranchName;
import com.tungsten.depbot.git.RemediationCheckoutManager;
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
import com.tungsten.depbot.run.RemediationRunService;
import com.tungsten.depbot.run.RunPaths;
import com.tungsten.depbot.git.RemediationChangeCommitter;
import com.tungsten.depbot.git.RemediationDiffPolicy;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fast regression tests for the {@code STOPPED_PLAN_DEVIATION_REQUIRED} self-report path: Implementation
 * itself, rather than a validation/Jenkins gate, is what decided the attempt could not proceed as
 * planned. This must route through the exact same repair cycle as any other failure -- and, on a second
 * such self-report, the exact same final-Human-Review path -- never a third implementation attempt.
 */
class PlanDeviationTest {

    private static final String RUN_ID = "run1";
    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-01-01T10:00:00Z"), ZoneOffset.UTC);
    private static final String SOURCE_REF = "refs/remotes/origin/release/9.2";
    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();
    private Path repo;
    private String verifiedSha;
    private String expectedBranch;

    @BeforeEach
    void createRepository() throws Exception {
        repo = GitTestRepos.createOriginAndSingleBranchClone(tempDir, "release/9.2");
        verifiedSha = GitTestRepos.shaOf(tempDir.resolve("origin.git"), "refs/heads/release/9.2");
        expectedBranch = RemediationBranchName.forRun(RUN_ID, SOURCE_REF, verifiedSha);
    }

    private Path runsRoot() {
        return tempDir.resolve("runs");
    }

    private VulnerabilityRemediationService service(FakeClaude fake) {
        ClaudeConfig config = new ClaudeConfig(fake.executable().toString(), "opus", 20, Duration.ofSeconds(60));
        RemediationRunService runService = new RemediationRunService(FIXED_CLOCK, runsRoot());
        ClaudeCodeExecutor executor = new ClaudeCodeExecutor(config, new ClaudeProcessRunner(), runService, FIXED_CLOCK);
        JenkinsConfig jenkinsConfig = new JenkinsConfig("https://jenkins.example.invalid", "job", "user", "token",
                Duration.ofSeconds(60), Duration.ofMillis(10));

        return new VulnerabilityRemediationService(
                repo,
                git,
                new RemoteRefsRefresher(git),
                new ManagedRepositoryRefresher(git, new SourceRefVerifier(git)),
                new RemediationCheckoutManager(git),
                new SourceRefVerifier(git),
                new BatchAnalysisService(executor, config, runService, new BatchAnalysisPromptRenderer()),
                new RemediationImplementationService(executor, config, runService,
                        new ImplementationPromptRenderer(), git,
                        new RemediationChangeCommitter(git, new RemediationDiffPolicy()),
                        Implementations.passingGate(), Implementations.passingBuildGate()),
                new JenkinsValidationService(new FakeJenkinsClient(), jenkinsConfig, git, runService),
                new HumanReviewService(executor, config, runService, new HumanReviewPromptRenderer()),
                runService);
    }

    private static VulnerabilityWorkItem workItem(String artifactId, String severity) {
        String coordinates = "com.example:" + artifactId;
        var library = Assessments.library("com.example", artifactId, "1.0");
        return new VulnerabilityWorkItem("com.example", artifactId, "1.0", severity, "1.1",
                List.of(Assessments.finding("CVE-2026-X-" + artifactId, severity.toLowerCase(Locale.ROOT),
                        library, "Upgrade " + coordinates + " to 1.1")));
    }

    private static String analysisJson(String coordinates, String groupId) {
        return """
                {
                  "schemaVersion": "1.0",
                  "findings": [
                    {
                      "coordinates": "%s",
                      "vulnerabilityIds": ["CVE-2026-X"],
                      "summary": "needs remediation",
                      "conclusion": "REMEDIATION_REQUIRED",
                      "remediationGroupId": "%s",
                      "evidence": ["evidence"]
                    }
                  ],
                  "remediationGroups": [
                    {
                      "groupId": "%s",
                      "memberCoordinates": ["%s"],
                      "groupingReason": "a single, unrelated finding",
                      "sourceRef": "origin/release/9.2",
                      "sourceCommitSha": "0123456789abcdef0123456789abcdef01234567",
                      "origin": "PROPERTY",
                      "dependencyRelationship": "declared directly",
                      "observedVersion": "1.0",
                      "recommendedRemediation": "raise the version",
                      "recommendedTargetVersion": "1.1",
                      "affectedFiles": ["pom.xml"],
                      "impactScore": 2,
                      "impactReason": "small change",
                      "automationSafety": "AUTOMATIC_ALLOWED",
                      "automationSafetyReason": "no coordinated dependency is involved",
                      "implementationPlan": ["raise the version"],
                      "validationPlan": ["run dependency:tree"],
                      "plannedChanges": [
                        {
                          "dependencyCoordinates": "%s",
                          "currentVersion": "1.0",
                          "targetVersion": "1.1",
                          "affectedFile": "pom.xml",
                          "changeType": "VERSION_BUMP",
                          "reason": "raises the version to close the CVE"
                        }
                      ]
                    }
                  ]
                }
                """.formatted(coordinates, groupId, groupId, coordinates, coordinates);
    }

    private static String humanReviewJson() {
        return """
                {
                  "schemaVersion": "1.0",
                  "coordinates": "com.example:artifact-a",
                  "vulnerabilitySummary": "a vulnerability",
                  "whyVulnerable": "an outdated version is pinned",
                  "dependencyOrigin": "declared directly",
                  "recommendedChange": "raise the version",
                  "relatedDependenciesToConsider": [],
                  "validationApproach": "run the test suite",
                  "openQuestions": [],
                  "risks": []
                }
                """;
    }

    private RejectedGroupOutcome readRejectedGroupOutcome(String unitId) throws Exception {
        Path path = runsRoot().resolve(RUN_ID).resolve("units").resolve(unitId)
                .resolve("human-review").resolve("attempt-1").resolve("rejected-group-outcome.json");
        return MAPPER.readValue(Files.readString(path, StandardCharsets.UTF_8), RejectedGroupOutcome.class);
    }

    private List<String> commitsAheadOfS0() throws Exception {
        String output = GitTestRepos.readOutput(repo, "git", "log", "--format=%H", expectedBranch, "--not", verifiedSha);
        return output.lines().filter(line -> !line.isBlank()).map(String::strip).toList();
    }

    @Test
    @DisplayName("Implementation self-reporting a plan deviation on attempt 1 triggers the repair cycle, "
            + "and if it happens again on attempt 2, routes to final Human Review with no third attempt")
    void selfReportedPlanDeviationOnBothAttemptsRoutesToHumanReviewWithNoThirdAttempt() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(
                        Assessments.answerContaining(analysisJson("com.example:artifact-a", "g-a"))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.planDeviationJson())))
                .respondingTo(ClaudePhase.HUMAN_REVIEW, Assessments.claudeOutput(
                        Assessments.answerContaining(humanReviewJson())))
                .build();

        List<VulnerabilityRemediationOutcome> outcomes = service(fake).remediateAll(RUN_ID, List.of(a));

        List<String> phases = fake.recordedPhaseSequence();
        assertEquals(2, phases.stream().filter(p -> p.equals("implementation")).count(),
                "exactly two implementation attempts, initial and repair -- never a third");

        // A single-group cohort where the only group was rejected on both attempts has zero accepted
        // candidates -- the shared branch itself is deleted entirely, so its absence (not an empty
        // "commits ahead of S0" list, which would fail with "unknown revision" on a nonexistent branch)
        // is the actual invariant to check.
        assertFalse(git.branchExistsLocally(repo, expectedBranch),
                "a cohort where nothing was accepted must not leave a shared branch behind");

        assertEquals(1, outcomes.size());
        assertFalse(outcomes.get(0).committed());
        assertTrue(outcomes.get(0).humanReviewOutcome() != null && outcomes.get(0).humanReviewOutcome().hasReport());

        RejectedGroupOutcome dossier = readRejectedGroupOutcome(RunPaths.unitId("critical", "com.example", "artifact-a"));
        assertEquals(RejectionStage.PLAN_DEVIATION_REQUIRED, dossier.stoppedAtStage());
        assertNotNull(dossier.failureReason());
    }
}
