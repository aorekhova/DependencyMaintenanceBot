package com.tungsten.depbot.remediation;

import com.tungsten.depbot.assessment.AutomationSafety;
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
import com.tungsten.depbot.git.RemediationCheckoutManager;
import com.tungsten.depbot.git.RemoteRefsRefresher;
import com.tungsten.depbot.git.SourceRefVerifier;
import com.tungsten.depbot.humanreview.HumanReviewPromptRenderer;
import com.tungsten.depbot.humanreview.HumanReviewService;
import com.tungsten.depbot.implementation.ImplementationPromptRenderer;
import com.tungsten.depbot.implementation.Implementations;
import com.tungsten.depbot.implementation.RemediationImplementationService;
import com.tungsten.depbot.jenkins.FakeJenkinsClient;
import com.tungsten.depbot.jenkins.JenkinsBuildResult;
import com.tungsten.depbot.jenkins.JenkinsConfig;
import com.tungsten.depbot.jenkins.JenkinsValidationService;
import com.tungsten.depbot.jenkins.JenkinsValidationStatus;
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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fast regression tests for {@link GroupStateWriter}/{@link GroupState} -- the per-group,
 * rewritten-in-full-every-time audit trail. Purely an audit trail: nothing in this codebase reads it back
 * to skip already-done work.
 */
class GroupStateWriterTest {

    private static final String RUN_ID = "run1";
    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-01-01T10:00:00Z"), ZoneOffset.UTC);
    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();
    private Path repo;

    @BeforeEach
    void createRepository() throws Exception {
        repo = GitTestRepos.createOriginAndSingleBranchClone(tempDir, "release/9.2");
    }

    private Path runsRoot() {
        return tempDir.resolve("runs");
    }

    private VulnerabilityRemediationService service(FakeClaude fake, FakeJenkinsClient jenkinsClient) {
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
                new JenkinsValidationService(jenkinsClient, jenkinsConfig, git, runService),
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

    private static String analysisJson(String automationSafety, String coordinates, String groupId) {
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
                      "automationSafety": "%s",
                      "automationSafetyReason": "see analysis",
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
                """.formatted(coordinates, groupId, groupId, coordinates, automationSafety, coordinates);
    }

    /** A literal version bump that {@code PlanConformanceGate}'s fast path can confirm without Maven. */
    private static String pomWithVersion(String artifactId, String version) {
        return """
                <project>
                  <dependencies>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>%s</artifactId>
                      <version>%s</version>
                    </dependency>
                  </dependencies>
                </project>
                """.formatted(artifactId, version);
    }

    private GroupState readGroupState(String unitId) throws Exception {
        Path path = runsRoot().resolve(RUN_ID).resolve("units").resolve(unitId).resolve("group-state.json");
        return MAPPER.readValue(Files.readString(path, StandardCharsets.UTF_8), GroupState.class);
    }

    @Test
    @DisplayName("a full ordinary-group lifecycle ends with FINAL_OUTCOME_DECIDED, one implementation "
            + "attempt, and ACCEPTED_ORDINARY, with every artifact path actually existing on disk")
    void fullOrdinaryLifecycleProducesConsistentFinalState() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(Assessments.answerContaining(
                        analysisJson("AUTOMATIC_ALLOWED", "com.example:artifact-a", "g-a"))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .creatingFile(ClaudePhase.IMPLEMENTATION, "pom.xml", pomWithVersion("artifact-a", "1.1"))
                .build();

        service(fake, new FakeJenkinsClient()).remediateAll(RUN_ID, List.of(a));

        String unitId = RunPaths.unitId("critical", "com.example", "artifact-a");
        GroupState state = readGroupState(unitId);

        assertEquals(GroupLifecycleStage.FINAL_OUTCOME_DECIDED, state.lastCompletedStage());
        assertEquals("g-a", state.groupId());
        assertEquals(List.of("com.example:artifact-a"), state.memberCoordinates());
        assertFalse(state.risky());
        assertEquals(AutomationSafety.AUTOMATIC_ALLOWED, state.automationSafety());
        assertNull(state.effectiveRiskReason(), "an ordinary, verifiable VERSION_BUMP is never risky");
        assertEquals(1, state.implementationAttempts().size());
        assertNotNull(state.finalOutcome());
        assertEquals(GroupFinalOutcomeKind.ACCEPTED_ORDINARY, state.finalOutcome().kind());
        assertNotNull(state.finalOutcome().commitSha());

        GroupState.ImplementationAttemptState attempt1 = state.implementationAttempts().get(0);
        assertEquals(1, attempt1.attemptNumber());
        assertNotNull(attempt1.implementationArtifactPath());
        assertTrue(Files.exists(Path.of(attempt1.implementationArtifactPath())),
                "the recorded implementation artifact path must actually exist on disk: "
                        + attempt1.implementationArtifactPath());
    }

    @Test
    @DisplayName("a risky group's final state has risky=true and ACCEPTED_RISKY on success")
    void riskyGroupFinalStateIsMarkedRiskyAndAcceptedRisky() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(Assessments.answerContaining(
                        analysisJson("HUMAN_REVIEW_REQUIRED", "com.example:artifact-a", "g-a"))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .creatingFile(ClaudePhase.IMPLEMENTATION, "pom.xml", pomWithVersion("artifact-a", "1.1"))
                .build();

        service(fake, new FakeJenkinsClient()).remediateAll(RUN_ID, List.of(a));

        String unitId = RunPaths.unitId("critical", "com.example", "artifact-a");
        GroupState state = readGroupState(unitId);

        assertTrue(state.risky());
        assertEquals(AutomationSafety.HUMAN_REVIEW_REQUIRED, state.automationSafety());
        assertNotNull(state.effectiveRiskReason());
        assertNotNull(state.finalOutcome());
        assertEquals(GroupFinalOutcomeKind.ACCEPTED_RISKY, state.finalOutcome().kind());
    }

    @Test
    @DisplayName("a repair-loop scenario ends with both implementation attempts recorded, in order")
    void repairLoopScenarioRecordsBothAttempts() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(Assessments.answerContaining(
                        analysisJson("AUTOMATIC_ALLOWED", "com.example:artifact-a", "g-a"))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .creatingFile(ClaudePhase.IMPLEMENTATION, "pom.xml", pomWithVersion("artifact-a", "1.1"))
                .build();

        // Same call-numbering convention as RepairLoopIntegrationTest: fail attempt 1's own Jenkins pair
        // (calls 1-2), let attempt 2's own pair (calls 3-4) fall through to the default SUCCESS result.
        FakeJenkinsClient jenkins = new FakeJenkinsClient();
        jenkins.respondOnCallNumber(2, new JenkinsBuildResult(
                JenkinsValidationStatus.FAILED, 2, "https://jenkins.example.invalid/job/x/2/", 10L,
                "Jenkins reported result FAILURE"));

        service(fake, jenkins).remediateAll(RUN_ID, List.of(a));

        String unitId = RunPaths.unitId("critical", "com.example", "artifact-a");
        GroupState state = readGroupState(unitId);

        assertEquals(GroupLifecycleStage.FINAL_OUTCOME_DECIDED, state.lastCompletedStage());
        assertEquals(2, state.implementationAttempts().size());
        assertEquals(1, state.implementationAttempts().get(0).attemptNumber());
        assertEquals(2, state.implementationAttempts().get(1).attemptNumber());
        assertEquals(GroupFinalOutcomeKind.ACCEPTED_ORDINARY, state.finalOutcome().kind());
    }

    @Test
    @DisplayName("GroupStateWriter.write rewrites the file in full -- a second write with different "
            + "content leaves no trace of the first")
    void writeRewritesFileInFullNeverAppends() throws Exception {
        RemediationRunService runService = new RemediationRunService(FIXED_CLOCK, runsRoot());
        GroupStateWriter writer = new GroupStateWriter(runService);

        GroupState first = new GroupState(
                null, RUN_ID, "g-a", List.of("com.example:artifact-a"), "refs/remotes/origin/release/9.2",
                "0123456789abcdef0123456789abcdef01234567", false, AutomationSafety.AUTOMATIC_ALLOWED,
                "reason", null, GroupLifecycleStage.IMPLEMENTATION_ATTEMPT_1, "2026-01-01T00:00:00Z",
                List.of(), null, null, null);
        writer.write("unit-1", first);

        GroupState second = new GroupState(
                null, RUN_ID, "g-a", List.of("com.example:artifact-a"), "refs/remotes/origin/release/9.2",
                "0123456789abcdef0123456789abcdef01234567", false, AutomationSafety.AUTOMATIC_ALLOWED,
                "reason", null, GroupLifecycleStage.FINAL_OUTCOME_DECIDED, "2026-01-01T00:01:00Z",
                List.of(), null,
                new GroupState.GroupFinalOutcome(GroupFinalOutcomeKind.ACCEPTED_ORDINARY, "abc123", null, "done"),
                null);
        writer.write("unit-1", second);

        String content = Files.readString(
                runsRoot().resolve(RUN_ID).resolve("units").resolve("unit-1").resolve("group-state.json"),
                StandardCharsets.UTF_8);
        assertTrue(content.contains("FINAL_OUTCOME_DECIDED"));
        assertTrue(content.contains("ACCEPTED_ORDINARY"));
        assertFalse(content.contains("IMPLEMENTATION_ATTEMPT_1"),
                "the first write's stage must not survive alongside the second, full rewrite: " + content);
    }
}
