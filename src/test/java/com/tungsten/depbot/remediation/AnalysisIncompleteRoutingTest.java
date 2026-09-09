package com.tungsten.depbot.remediation;

import com.tungsten.depbot.assessment.Assessments;
import com.tungsten.depbot.assessment.BatchAnalysisPromptRenderer;
import com.tungsten.depbot.assessment.BatchAnalysisService;
import com.tungsten.depbot.assessment.RemediationVerdict;
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
import com.tungsten.depbot.progress.RemediationProgressListener;
import com.tungsten.depbot.progress.RemediationStep;
import com.tungsten.depbot.git.RemediationChangeCommitter;
import com.tungsten.depbot.git.RemediationDiffPolicy;
import com.tungsten.depbot.run.RemediationRunService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fast regression tests for how {@link VulnerabilityRemediationService} routes a batch whose analysis
 * came back {@link com.tungsten.depbot.assessment.BatchAnalysisStatus#INCOMPLETE} -- a report-only
 * finalization call that never actually examined anything must stop the whole run before any finding is
 * routed, not be treated as "0 findings requiring remediation" or as a normal Human Review outcome.
 * Deliberately minimal: fakes and a small temporary git repository, no real Maven, Jenkins, Claude or
 * network.
 */
class AnalysisIncompleteRoutingTest {

    private static final String RUN_ID = "run1";
    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-01-01T10:00:00Z"), ZoneOffset.UTC);

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

    private VulnerabilityRemediationService service(FakeClaude fake, RemediationProgressListener progress) {
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
                runService,
                progress);
    }

    private static VulnerabilityWorkItem workItem(String artifactId, String severity) {
        String coordinates = "com.example:" + artifactId;
        var library = Assessments.library("com.example", artifactId, "1.0");
        return new VulnerabilityWorkItem("com.example", artifactId, "1.0", severity, "1.1",
                List.of(Assessments.finding("CVE-2026-X-" + artifactId, severity.toLowerCase(java.util.Locale.ROOT),
                        library, "Upgrade " + coordinates + " to 1.1")));
    }

    private static String placeholderAnalysisJson(String... coordinates) {
        StringBuilder findings = new StringBuilder();
        for (int i = 0; i < coordinates.length; i++) {
            if (i > 0) {
                findings.append(",\n");
            }
            findings.append("""
                    {
                      "coordinates": "%s",
                      "vulnerabilityIds": ["CVE-2026-X"],
                      "summary": "Not examined",
                      "conclusion": "INCONCLUSIVE",
                      "remediationGroupId": null,
                      "evidence": [],
                      "risks": ["time ran out before this finding could be looked at"]
                    }""".formatted(coordinates[i]));
        }
        return """
                {
                  "schemaVersion": "1.0",
                  "findings": [
                %s
                  ],
                  "remediationGroups": []
                }
                """.formatted(findings.toString().indent(4));
    }

    /** Records every {@code stepFinished} outcome string, keyed by step, in call order. */
    private static final class RecordingProgressListener implements RemediationProgressListener {
        private final List<String> assessmentOutcomes = new ArrayList<>();

        @Override
        public void stepStarting(RemediationStep step, String coordinates, String detail) {
            // Nothing to record.
        }

        @Override
        public void stepFinished(RemediationStep step, String coordinates, String outcome) {
            if (step == RemediationStep.ASSESSMENT) {
                assessmentOutcomes.add(outcome);
            }
        }
    }

    // ---- 5. an incomplete analysis runs no automatic remediation and no per-finding Human Review ----

    @Test
    @DisplayName("an incomplete analysis stops the run before any group runs and before any per-finding "
            + "Human Review is started")
    void incompleteAnalysisRunsNoAutomaticRemediationOrHumanReviewFanOut() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        VulnerabilityWorkItem b = workItem("artifact-b", "HIGH");
        String primaryResponse = "{\"is_error\":true,\"subtype\":\"error_max_turns\",\"session_id\":\"sess-1\"}";
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, primaryResponse)
                .respondingToAssessmentSecondAttempt(Assessments.claudeOutput(
                        placeholderAnalysisJson(a.coordinates(), b.coordinates())))
                .build();

        List<VulnerabilityRemediationOutcome> outcomes =
                service(fake, RemediationProgressListener.none()).remediateAll(RUN_ID, List.of(a, b));

        assertEquals(List.of("assessment", "assessment-second-attempt"), fake.recordedPhaseSequence(),
                "neither implementation nor human-review may ever run for an incomplete analysis");

        assertEquals(2, outcomes.size());
        for (VulnerabilityRemediationOutcome outcome : outcomes) {
            assertEquals(RemediationStage.ASSESSMENT_INCOMPLETE, outcome.reachedStage());
            assertFalse(outcome.committed(), "no automatic remediation group may run");
            assertFalse(outcome.humanReviewRequired(),
                    "an incomplete analysis must never be masked as a normal Human Review outcome");
            assertNull(outcome.implementation());
            assertNull(outcome.humanReviewOutcome());
            assertTrue(outcome.stopReason() != null && outcome.stopReason().contains("Vulnerability Analysis incomplete"),
                    outcome.stopReason());
        }

        CohortsIndex cohortsIndex = new CohortsIndexJsonReader().read(
                runsRoot().resolve(RUN_ID).resolve(CohortsIndexJsonReader.FILE_NAME));
        assertTrue(cohortsIndex.cohorts().isEmpty(), "no cohort may be produced from an incomplete analysis");

        RemediationSummary summary = RemediationSummaryBuilder.build(
                RUN_ID, "2026-01-01T10:00:00Z", "opus", repo.toString(), null, outcomes);
        assertEquals(2, summary.analysisIncompleteFindingCount(),
                "both findings must be counted under their own, honestly-batch-scoped name");
        assertEquals(1, summary.analysisIncompleteBatchCount(),
                "one incomplete batch, however many findings it covered -- never counted per finding");
        assertEquals(0, summary.needsAHumanCount(),
                "an incomplete analysis must never inflate \"needs a human\"/\"Failures\" by one per finding");
        assertEquals(0, summary.failureCount(),
                "ten findings sharing one incomplete batch are one pipeline stoppage, not ten failures");
        for (RemediationSummaryEntry entry : summary.libraries()) {
            assertEquals(GroupOutcomeState.ANALYSIS_INCOMPLETE, entry.groupOutcomeState());
        }
    }

    // ---- 6. the console/progress message never claims "0 requiring remediation" --------------------

    @Test
    @DisplayName("the assessment step's own progress message clearly says the analysis is incomplete, "
            + "never \"0 requiring remediation\"")
    void incompleteAnalysisProgressMessageNeverClaimsZeroRequiringRemediation() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        String primaryResponse = "{\"is_error\":true,\"subtype\":\"error_max_turns\",\"session_id\":\"sess-2\"}";
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, primaryResponse)
                .respondingToAssessmentSecondAttempt(
                        Assessments.claudeOutput(placeholderAnalysisJson(a.coordinates())))
                .build();

        RecordingProgressListener progress = new RecordingProgressListener();
        service(fake, progress).remediateAll(RUN_ID, List.of(a));

        assertEquals(1, progress.assessmentOutcomes.size());
        String message = progress.assessmentOutcomes.get(0);
        assertTrue(message.contains("Vulnerability Analysis incomplete"), message);
        assertFalse(message.contains("requiring remediation"), message);
    }

    // ---- 7. a schema-repaired analysis routes normally -- never a per-finding Human Review fan-out ----

    private static String noActionRequiredFinding(String coordinates) {
        return """
                {
                  "coordinates": "%s",
                  "vulnerabilityIds": ["CVE-2026-X"],
                  "summary": "not actually present on this ref",
                  "conclusion": "NO_ACTION_REQUIRED",
                  "remediationGroupId": null,
                  "evidence": ["dependency:tree does not list it"],
                  "noActionBasis": "DEPENDENCY_NOT_PRESENT"
                }""".formatted(coordinates);
    }

    /** One REMEDIATION_REQUIRED group (HUMAN_REVIEW_REQUIRED, so it is deliberately reviewed once) plus
     *  five NO_ACTION_REQUIRED findings -- the same "one malformed group amid several libraries" shape as
     *  the production pilot. {@code includeChangeType} toggles the exact defect that pilot hit. */
    private static String mixedBatchJson(VulnerabilityWorkItem group, List<VulnerabilityWorkItem> noAction,
            boolean includeChangeType) {
        StringBuilder findings = new StringBuilder("""
                {
                  "coordinates": "%s",
                  "vulnerabilityIds": ["CVE-2026-1"],
                  "summary": "needs a coordinated review",
                  "conclusion": "REMEDIATION_REQUIRED",
                  "remediationGroupId": "g-a",
                  "evidence": ["evidence"]
                }""".formatted(group.coordinates()));
        for (VulnerabilityWorkItem item : noAction) {
            findings.append(",\n").append(noActionRequiredFinding(item.coordinates()));
        }
        String changeTypeLine = includeChangeType ? "\"changeType\": \"OTHER\"," : "";
        return """
                {
                  "schemaVersion": "1.0",
                  "findings": [
                %s
                  ],
                  "remediationGroups": [
                    {
                      "groupId": "g-a",
                      "memberCoordinates": ["%s"],
                      "groupingReason": "a single finding",
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
                      "automationSafety": "HUMAN_REVIEW_REQUIRED",
                      "automationSafetyReason": "a coordinated dependency requires a human to authorise it",
                      "implementationPlan": ["raise the version"],
                      "validationPlan": ["run dependency:tree"],
                      "plannedChanges": [
                        {
                          "dependencyCoordinates": "%s",
                          "currentVersion": "1.0",
                          "targetVersion": "1.1",
                          "affectedFile": "pom.xml",
                          %s
                          "reason": "raises the version to close the CVE"
                        }
                      ]
                    }
                  ]
                }
                """.formatted(findings.toString().indent(4), group.coordinates(), group.coordinates(), changeTypeLine);
    }

    private static String humanReviewJson(String coordinates) {
        return """
                {
                  "schemaVersion": "1.0",
                  "coordinates": "%s",
                  "vulnerabilitySummary": "a vulnerability",
                  "whyVulnerable": "an outdated version is pinned",
                  "dependencyOrigin": "declared directly",
                  "recommendedChange": "raise the version",
                  "relatedDependenciesToConsider": [],
                  "validationApproach": "run the test suite",
                  "openQuestions": [],
                  "risks": []
                }
                """.formatted(coordinates);
    }

    @Test
    @DisplayName("a batch whose analysis document was schema-malformed (missing changeType) but "
            + "successfully schema-repaired routes every finding normally -- never fans out to individual "
            + "Human Review the way a genuinely FAILED batch would")
    void schemaRepairedAnalysisNeverFansOutToPerFindingHumanReview() throws Exception {
        VulnerabilityWorkItem group = workItem("artifact-a", "CRITICAL");
        List<VulnerabilityWorkItem> noAction = List.of(
                workItem("artifact-b", "HIGH"), workItem("artifact-c", "HIGH"),
                workItem("artifact-d", "MEDIUM"), workItem("artifact-e", "MEDIUM"),
                workItem("artifact-f", "LOW"));
        List<VulnerabilityWorkItem> all = new ArrayList<>(noAction);
        all.add(0, group);

        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT,
                        Assessments.claudeOutput(Assessments.answerContaining(
                                mixedBatchJson(group, noAction, false))))
                .respondingToAssessmentSchemaRepair(
                        Assessments.claudeOutput(Assessments.answerContaining(
                                mixedBatchJson(group, noAction, true))))
                .respondingTo(ClaudePhase.HUMAN_REVIEW,
                        Assessments.claudeOutput(Assessments.answerContaining(humanReviewJson(group.coordinates()))))
                .build();

        List<VulnerabilityRemediationOutcome> outcomes =
                service(fake, RemediationProgressListener.none()).remediateAll(RUN_ID, all);

        // The HUMAN_REVIEW_REQUIRED group is genuinely attempted through its own isolated, risky
        // singleton cohort before its Human Review report is written (unscripted IMPLEMENTATION calls
        // here simply fail to produce a usable report and retry once, exactly as attemptGroup's own
        // bounded repair loop already does) -- what matters for this regression is that Human Review
        // itself is invoked exactly once for the whole batch, never once per finding the way a genuinely
        // FAILED/unusable batch fans out.
        assertTrue(fake.recordedPhaseSequence().contains("assessment"));
        assertTrue(fake.recordedPhaseSequence().contains("assessment-schema-repair"));
        long humanReviewCalls = fake.recordedPhaseSequence().stream()
                .filter(phase -> phase.equals("human-review")).count();
        assertEquals(1, humanReviewCalls,
                "exactly one Human Review call, for the one HUMAN_REVIEW_REQUIRED group -- never one per "
                        + "finding the way a FAILED/unusable batch would fan out: " + fake.recordedPhaseSequence());

        assertEquals(6, outcomes.size());
        for (VulnerabilityRemediationOutcome outcome : outcomes) {
            if (outcome.coordinates().equals(group.coordinates())) {
                assertTrue(outcome.humanReviewRequired(),
                        "the one group Claude itself flagged HUMAN_REVIEW_REQUIRED must still get its report");
            } else {
                assertFalse(outcome.humanReviewRequired(),
                        "a NO_ACTION_REQUIRED finding must never be individually Human-Reviewed: "
                                + outcome.coordinates());
                assertEquals(RemediationVerdict.NO_ACTION_REQUIRED, outcome.verdict());
            }
        }
    }
}
