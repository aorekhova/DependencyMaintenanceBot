package com.tungsten.depbot.remediation;

import com.tungsten.depbot.assessment.Assessments;
import com.tungsten.depbot.assessment.BatchAnalysisPromptRenderer;
import com.tungsten.depbot.assessment.BatchAnalysisService;
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
import com.tungsten.depbot.jenkins.JenkinsConfig;
import com.tungsten.depbot.jenkins.JenkinsValidationService;
import com.tungsten.depbot.git.RemediationChangeCommitter;
import com.tungsten.depbot.git.RemediationDiffPolicy;
import com.tungsten.depbot.run.RemediationRunService;
import com.tungsten.depbot.validation.FullBuildValidationGate;
import com.tungsten.depbot.validation.RemediationValidationGate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fast regression tests for the partial-analysis fallback: what happens when both Vulnerability
 * Analysis attempts run out of turns or time. Deliberately minimal -- fakes and a small temporary git
 * repository, no real Maven, Jenkins, Claude or network.
 */
class PartialAnalysisFallbackTest {

    private static final String RUN_ID = "run1";
    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-01-01T10:00:00Z"), ZoneOffset.UTC);
    private static final String MAX_TURNS_RESPONSE =
            "{\"is_error\":true,\"subtype\":\"error_max_turns\",\"session_id\":\"sess-1\"}";
    private static final String MAX_TURNS_RESPONSE_2 =
            "{\"is_error\":true,\"subtype\":\"error_max_turns\",\"session_id\":\"sess-2\"}";

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
        return service(fake, jenkinsClient, Implementations.passingGate(), Implementations.passingBuildGate());
    }

    private VulnerabilityRemediationService service(
            FakeClaude fake, FakeJenkinsClient jenkinsClient,
            RemediationValidationGate validationGate, FullBuildValidationGate fullBuildGate) {
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
                        validationGate, fullBuildGate),
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

    /** One finding + one AUTOMATIC_ALLOWED group per {@code (coordinates, groupId)} pair, on {@link #SOURCE_REF}. */
    private static String analysisJson(String[]... coordinatesAndGroupIds) {
        StringBuilder findings = new StringBuilder();
        StringBuilder groups = new StringBuilder();
        for (int i = 0; i < coordinatesAndGroupIds.length; i++) {
            String coordinates = coordinatesAndGroupIds[i][0];
            String groupId = coordinatesAndGroupIds[i][1];
            if (i > 0) {
                findings.append(",\n");
                groups.append(",\n");
            }
            findings.append("""
                    {
                      "coordinates": "%s",
                      "vulnerabilityIds": ["CVE-2026-X"],
                      "summary": "needs remediation",
                      "conclusion": "REMEDIATION_REQUIRED",
                      "remediationGroupId": "%s",
                      "evidence": ["evidence"]
                    }""".formatted(coordinates, groupId));
            groups.append("""
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
                          "affectedFile": "a.txt",
                          "changeType": "OTHER",
                          "reason": "requires editing a.txt directly to close the CVE, no mechanical version bump"
                        }
                      ]
                    }""".formatted(groupId, coordinates, coordinates));
        }
        return """
                {
                  "schemaVersion": "1.0",
                  "findings": [
                %s
                  ],
                  "remediationGroups": [
                %s
                  ]
                }
                """.formatted(findings.toString().indent(4), groups.toString().indent(4));
    }

    private static String humanReviewJson() {
        return """
                {
                  "schemaVersion": "1.0",
                  "coordinates": "com.example:artifact",
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

    private CohortsIndex cohortsIndex() {
        return new CohortsIndexJsonReader().read(
                runsRoot().resolve(RUN_ID).resolve(CohortsIndexJsonReader.FILE_NAME));
    }

    // ---- 1. attempt1 COMPLETE -> attempt2 never runs ------------------------------------------------

    @Test
    @DisplayName("attempt1 completing cleanly means attempt2 never runs at all")
    void attempt1CompleteMeansAttempt2NeverRuns() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(Assessments.answerContaining(
                        analysisJson(new String[] {"com.example:artifact-a", "g-a"}))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(Implementations.completedJson()))
                .creatingFileOnInvocation(2, "a.txt", "content-a\n")
                .build();

        service(fake, new FakeJenkinsClient()).remediateAll(RUN_ID, List.of(a));

        assertEquals(List.of("assessment", "implementation"), fake.recordedPhaseSequence(),
                "attempt1 completed cleanly -- there must be no second analysis attempt at all");
        assertFalse(cohortsIndex().cohorts().isEmpty(), "the ordinary pipeline must still have succeeded");
    }

    // ---- 2. attempt1 TIMEOUT -> attempt2 gets attempt1's progress -> attempt2 COMPLETE -> routing ---

    @Test
    @DisplayName("attempt1 running out of turns, then attempt2 completing, resumes the ordinary pipeline")
    void secondAttemptCompletingResumesOrdinaryRouting() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, MAX_TURNS_RESPONSE)
                .respondingToAssessmentSecondAttempt(Assessments.claudeOutput(Assessments.answerContaining(
                        analysisJson(new String[] {"com.example:artifact-a", "g-a"}))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(Implementations.completedJson()))
                .creatingFileOnInvocation(3, "a.txt", "content-a\n")
                .build();

        service(fake, new FakeJenkinsClient()).remediateAll(RUN_ID, List.of(a));

        assertEquals(List.of("assessment", "assessment-second-attempt", "implementation"),
                fake.recordedPhaseSequence());
        assertFalse(cohortsIndex().cohorts().isEmpty(), "a second attempt that completes must resume normal routing");
    }

    // ---- 3. both attempts run out of room, direction is known -> Implementation gets a chance ------

    @Test
    @DisplayName("both analysis attempts running out of room, with a known upgrade direction, still lets "
            + "the Remediation Engineer commit the change -- through its own risky singleton cohort, since "
            + "Java cannot independently confirm an unfinished analysis is safe to run unattended")
    void bothAttemptsExhaustedWithKnownDirectionLetsImplementationSucceed() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, MAX_TURNS_RESPONSE)
                .respondingToAssessmentSecondAttempt(MAX_TURNS_RESPONSE_2)
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(Implementations.completedJson()))
                .creatingFileOnInvocation(3, "a.txt", "content-a\n")
                .build();

        List<VulnerabilityRemediationOutcome> outcomes =
                service(fake, new FakeJenkinsClient()).remediateAll(RUN_ID, List.of(a));

        assertEquals(List.of("assessment", "assessment-second-attempt", "implementation"),
                fake.recordedPhaseSequence());

        CohortsIndex index = cohortsIndex();
        assertFalse(index.cohorts().isEmpty(), "a known direction must give the Remediation Engineer a real "
                + "chance to commit, never a hard stop");
        assertEquals(RemediationCohort.CohortKind.RISKY_SINGLE_GROUP, index.cohorts().get(0).effectiveKind(),
                "an unfinished analysis can never be independently confirmed AUTOMATIC_ALLOWED, so this must "
                        + "always land in its own risky singleton cohort, never the ordinary shared one");
        assertEquals(1, index.cohorts().get(0).commits().size());
        assertTrue(index.cohorts().get(0).commits().get(0).groupId().startsWith("partial-"),
                "the synthetic fallback group must be clearly distinguishable from a real analysis group");

        assertEquals(1, outcomes.size());
        assertTrue(outcomes.get(0).committed());
    }

    // ---- 4. both attempts run out of room, direction cannot be determined -> Human Review ----------

    @Test
    @DisplayName("both analysis attempts running out of room, with no determinable direction, routes to "
            + "Human Review rather than guessing")
    void bothAttemptsExhaustedWithNoDeterminableDirectionGoesToHumanReview() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, MAX_TURNS_RESPONSE)
                .respondingToAssessmentSecondAttempt(MAX_TURNS_RESPONSE_2)
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(Implementations.blockedJson()))
                .respondingTo(ClaudePhase.HUMAN_REVIEW, Assessments.claudeOutput(humanReviewJson()))
                .build();

        List<VulnerabilityRemediationOutcome> outcomes =
                service(fake, new FakeJenkinsClient()).remediateAll(RUN_ID, List.of(a));

        assertTrue(cohortsIndex().cohorts().isEmpty(), "a direction that could not be determined must never "
                + "be guessed at or committed");
        assertEquals(1, outcomes.size());
        assertFalse(outcomes.get(0).committed());
        assertTrue(outcomes.get(0).humanReviewOutcome() != null && outcomes.get(0).humanReviewOutcome().hasReport(),
                "the finding must reach a real Human Review report, not be silently dropped");
        assertEquals("master", GitTestRepos.currentBranch(repo),
                "the checkout must be restored to wherever it started -- nothing left uncommitted or half-applied");
        assertTrue(git.isClean(repo));
    }

    // ---- 5. both attempts run out of room, Implementation cannot safely finish -> rollback + Human Review

    @Test
    @DisplayName("both analysis attempts running out of room, with Implementation reporting success but the "
            + "existing dependency-validation gate refusing it, still safely rolls back to Human Review")
    void bothAttemptsExhaustedButValidationGateRefusesStillRollsBackSafely() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, MAX_TURNS_RESPONSE)
                .respondingToAssessmentSecondAttempt(MAX_TURNS_RESPONSE_2)
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(Implementations.completedJson()))
                .respondingTo(ClaudePhase.HUMAN_REVIEW, Assessments.claudeOutput(humanReviewJson()))
                .creatingFileOnInvocation(3, "a.txt", "content-a\n")
                .build();

        String baseSha = git.currentHeadSha(repo);
        List<VulnerabilityRemediationOutcome> outcomes = service(fake, new FakeJenkinsClient(),
                Implementations.failingGate("1.1 does not resolve offline"), Implementations.passingBuildGate())
                .remediateAll(RUN_ID, List.of(a));

        assertTrue(cohortsIndex().cohorts().isEmpty(),
                "the dependency-resolution gate refusing it must still block automatic remediation");
        assertEquals(1, outcomes.size());
        assertFalse(outcomes.get(0).committed(), "a gate refusal must never leave the commit in place");
        assertTrue(outcomes.get(0).humanReviewOutcome() != null && outcomes.get(0).humanReviewOutcome().hasReport());

        assertEquals(baseSha, git.currentHeadSha(repo),
                "the repository must be safely restored to the verified tip it started from");
        assertTrue(git.isClean(repo));
    }

    // ---- 6. an already-decided HUMAN_REVIEW_REQUIRED/AUTOMATION_BLOCKED verdict is never bypassed ----

    /** A single-line, best-effort-recoverable partial document naming one finding's own safety verdict. */
    private static String recoveredSafetyVerdictJson(String coordinates, String automationSafety) {
        return "{\"schemaVersion\":\"1.0\",\"findings\":[],\"remediationGroups\":[{\"groupId\":\"g-recovered\","
                + "\"memberCoordinates\":[\"" + coordinates + "\"],\"automationSafety\":\"" + automationSafety
                + "\",\"automationSafetyReason\":\"already decided before running out of room\"}]}";
    }

    private static String maxTurnsResponseWithRecoveredResult(String resultJson) {
        return "{\"is_error\":true,\"subtype\":\"error_max_turns\",\"session_id\":\"sess-recovered\",\"result\":\""
                + resultJson.replace("\\", "\\\\").replace("\"", "\\\"") + "\"}";
    }

    @Test
    @DisplayName("a HUMAN_REVIEW_REQUIRED verdict already recovered from partial evidence skips the "
            + "Implementation fallback entirely and goes straight to Human Review")
    void recoveredHumanReviewRequiredVerdictSkipsImplementationFallback() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, MAX_TURNS_RESPONSE)
                .respondingToAssessmentSecondAttempt(maxTurnsResponseWithRecoveredResult(
                        recoveredSafetyVerdictJson(a.coordinates(), "HUMAN_REVIEW_REQUIRED")))
                .respondingTo(ClaudePhase.HUMAN_REVIEW, Assessments.claudeOutput(humanReviewJson()))
                .build();

        List<VulnerabilityRemediationOutcome> outcomes =
                service(fake, new FakeJenkinsClient()).remediateAll(RUN_ID, List.of(a));

        assertFalse(fake.recordedPhaseSequence().contains("implementation"),
                "an already-decided HUMAN_REVIEW_REQUIRED verdict must never be bypassed by attempting "
                        + "automatic remediation, even from a timeout fallback");
        assertTrue(cohortsIndex().cohorts().isEmpty());
        assertEquals(1, outcomes.size());
        assertFalse(outcomes.get(0).committed());
        assertTrue(outcomes.get(0).humanReviewOutcome() != null && outcomes.get(0).humanReviewOutcome().hasReport(),
                "the finding must still reach a real Human Review report, not be silently dropped");
    }

    @Test
    @DisplayName("an AUTOMATION_BLOCKED verdict already recovered from partial evidence skips the "
            + "Implementation fallback entirely and goes straight to Human Review")
    void recoveredAutomationBlockedVerdictSkipsImplementationFallback() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, MAX_TURNS_RESPONSE)
                .respondingToAssessmentSecondAttempt(maxTurnsResponseWithRecoveredResult(
                        recoveredSafetyVerdictJson(a.coordinates(), "AUTOMATION_BLOCKED")))
                .respondingTo(ClaudePhase.HUMAN_REVIEW, Assessments.claudeOutput(humanReviewJson()))
                .build();

        List<VulnerabilityRemediationOutcome> outcomes =
                service(fake, new FakeJenkinsClient()).remediateAll(RUN_ID, List.of(a));

        assertFalse(fake.recordedPhaseSequence().contains("implementation"),
                "an already-decided AUTOMATION_BLOCKED verdict must never be bypassed by attempting "
                        + "automatic remediation, even from a timeout fallback");
        assertTrue(cohortsIndex().cohorts().isEmpty());
        assertEquals(1, outcomes.size());
        assertFalse(outcomes.get(0).committed());
        assertTrue(outcomes.get(0).humanReviewOutcome() != null && outcomes.get(0).humanReviewOutcome().hasReport());
    }

    // ---- 7. genuinely related findings recovered as one group are never split into contradicting attempts

    @Test
    @DisplayName("two findings recovered as one real remediation group are clustered into a single "
            + "fallback attempt, never split into independent, potentially contradictory ones")
    void recoveredGroupMembershipClustersRelatedFindingsIntoOneFallbackAttempt() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        VulnerabilityWorkItem b = workItem("artifact-b", "HIGH");
        String recoveredFamilyJson = "{\"schemaVersion\":\"1.0\",\"findings\":[],\"remediationGroups\":["
                + "{\"groupId\":\"g-family\",\"memberCoordinates\":[\"" + a.coordinates() + "\",\""
                + b.coordinates() + "\"],\"sourceRef\":\"origin/release/9.2\",\"automationSafety\":\"AUTOMATIC_ALLOWED\","
                + "\"automationSafetyReason\":\"safe to automate together\","
                + "\"implementationPlan\":[\"raise both versions together\"]}]}";
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, MAX_TURNS_RESPONSE)
                .respondingToAssessmentSecondAttempt(maxTurnsResponseWithRecoveredResult(recoveredFamilyJson))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(Implementations.completedJson()))
                .creatingFileOnInvocation(3, "a.txt", "content-a\n")
                .build();

        List<VulnerabilityRemediationOutcome> outcomes =
                service(fake, new FakeJenkinsClient()).remediateAll(RUN_ID, List.of(a, b));

        long implementationCalls = fake.recordedPhaseSequence().stream()
                .filter(phase -> phase.equals("implementation")).count();
        assertEquals(1, implementationCalls,
                "two findings recovered as one real group must reach the Remediation Engineer together, "
                        + "in a single call -- never as two separate, potentially contradictory attempts");

        CohortsIndex index = cohortsIndex();
        assertFalse(index.cohorts().isEmpty());
        assertEquals(1, index.cohorts().get(0).commits().size(), "one shared commit for the whole family");
        assertEquals("g-family", index.cohorts().get(0).commits().get(0).groupId());

        assertEquals(2, outcomes.size());
        assertTrue(outcomes.get(0).committed());
        assertTrue(outcomes.get(1).committed());
    }
}
