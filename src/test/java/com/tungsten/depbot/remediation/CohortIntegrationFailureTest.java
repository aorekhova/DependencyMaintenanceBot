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
import com.tungsten.depbot.jenkins.JenkinsBuildResult;
import com.tungsten.depbot.jenkins.JenkinsConfig;
import com.tungsten.depbot.jenkins.JenkinsValidationService;
import com.tungsten.depbot.jenkins.JenkinsValidationStatus;
import com.tungsten.depbot.publication.HumanReviewReportMarkdownRenderer;
import com.tungsten.depbot.humanreview.HumanReviewReport;
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
 * Fast regression tests for the cohort-level final-integration-Jenkins-failure dossier: every group in a
 * cohort is individually accepted (its own cumulative Jenkins succeeds), but the fully assembled branch
 * fails a SEPARATE final integration Jenkins gate -- the dossier must cover the whole accepted set,
 * anchored to S0, and must never single out one specific group as "the" cause. Real temporary git
 * repositories and {@link FakeClaude}/{@link FakeJenkinsClient}, no real Maven, no real Jenkins polling,
 * no network.
 */
class CohortIntegrationFailureTest {

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
                          "affectedFile": "%s",
                          "changeType": "VERSION_BUMP",
                          "reason": "raises the version to close the CVE"
                        }
                      ]
                    }""".formatted(groupId, coordinates, coordinates, pomPathFor(coordinates)));
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

    /** A distinct, deterministic pom.xml path per coordinate, each in its own subdirectory -- {@code
     * PlanConformanceGate} discovers a POM by its exact filename ("pom.xml"), matching real Maven
     * convention, so each coordinate needs its own directory rather than a same-directory name variant. */
    private static String pomPathFor(String coordinates) {
        return coordinates.substring(coordinates.indexOf(':') + 1) + "/pom.xml";
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

    private static String humanReviewJson() {
        return """
                {
                  "schemaVersion": "1.0",
                  "coordinates": "com.example:artifact-a, com.example:artifact-b",
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

    /** Mirrors {@code VulnerabilityRemediationService#cohortUnitId} for an ORDINARY (non-risky) cohort --
     *  a short, stable hash of the branch name, not the branch name itself sanitised verbatim (see
     *  pilot 20260908-220923-771c06: a directory name built from the full branch name was too long for
     *  ordinary Windows tooling to read). */
    private static String cohortUnitId(String branchName) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(branchName.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return "cohort-" + hex.substring(0, 10);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    @DisplayName("every group individually accepted, but final integration Jenkins fails: dossier covers "
            + "the whole set, anchored to S0, never blaming one group; each accepted group's own "
            + "group-state.json is stamped BLOCKED_BY_COHORT_INTEGRATION_FAILURE")
    void everyGroupAcceptedButFinalIntegrationFailsProducesWholeCohortDossier() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        VulnerabilityWorkItem b = workItem("artifact-b", "HIGH");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(Assessments.answerContaining(
                        analysisJson(new String[] {"com.example:artifact-a", "g-a"},
                                new String[] {"com.example:artifact-b", "g-b"}))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .respondingTo(ClaudePhase.HUMAN_REVIEW, Assessments.claudeOutput(
                        Assessments.answerContaining(humanReviewJson())))
                .creatingFileOnInvocation(2, pomPathFor("com.example:artifact-a"), pomWithVersion("artifact-a", "1.1"))
                .creatingFileOnInvocation(3, pomPathFor("com.example:artifact-b"), pomWithVersion("artifact-b", "1.1"))
                .build();

        // Group A's own cumulative Jenkins pair = calls 1-2, group B's = calls 3-4 (both succeed via the
        // default canned SUCCESS), the final integration pair = calls 5-6 -- fail call 6, its own
        // waitForCompletion (see RepairLoopIntegrationTest for the exact 2N-numbering rationale).
        FakeJenkinsClient jenkins = new FakeJenkinsClient();
        jenkins.respondOnCallNumber(6, new JenkinsBuildResult(
                JenkinsValidationStatus.FAILED, 3, "https://jenkins.example.invalid/job/x/3/", 10L,
                "Jenkins reported result FAILURE"));

        List<VulnerabilityRemediationOutcome> outcomes = service(fake, jenkins).remediateAll(RUN_ID, List.of(a, b));

        // Both groups' own commits exist on the shared branch (never deleted just because the later,
        // separate integration gate failed), but the cohort itself is not marked ready to publish.
        assertTrue(git.branchExistsLocally(repo, expectedBranch));
        assertTrue(cohortsIndex().cohorts().isEmpty(),
                "a cohort whose final integration gate failed must never be marked ready to publish");
        assertEquals(2, outcomes.size());

        String unitId = "integration__" + cohortUnitId(expectedBranch);
        Path dossierPath = runsRoot().resolve(RUN_ID).resolve("units").resolve(unitId)
                .resolve("human-review").resolve("attempt-1").resolve("cohort-integration-failure.json");
        assertTrue(Files.exists(dossierPath), "the cohort-level dossier must be persisted");

        // Windows-path-oriented regression (production incident, pilot 20260908-220923-771c06):
        // PowerShell's Compress-Archive failed to recurse into a run directory once a unit directory name
        // repeated the full run id, a fully sanitised source ref, and a branch prefix. The unit directory
        // name itself -- not the whole path, which also depends on the caller's own checkout location --
        // must stay short regardless of how long the source ref or branch name that produced it was.
        assertTrue(unitId.length() <= 40,
                "unit directory names must stay short and Windows-tool-friendly, not repeat the run id, "
                        + "the full sanitised source ref or the branch prefix already implied by the parent "
                        + "run directory: " + unitId);
        CohortIntegrationFailureOutcome dossier = MAPPER.readValue(
                Files.readString(dossierPath, StandardCharsets.UTF_8), CohortIntegrationFailureOutcome.class);

        assertEquals(verifiedSha, dossier.verifiedSourceSha(), "anchored to S0, never a per-group base SHA");
        assertEquals(2, dossier.acceptedGroupIds().size());
        assertTrue(dossier.acceptedGroupIds().containsAll(List.of("g-a", "g-b")));
        assertNotNull(dossier.cumulativePatch());
        assertTrue(dossier.cumulativePatch().contains("artifact-a") && dossier.cumulativePatch().contains("artifact-b"),
                "the cumulative patch must cover both accepted groups' own changes: " + dossier.cumulativePatch());
        assertNotNull(dossier.reproductionInstructions());
        assertTrue(dossier.reproductionInstructions().contains(verifiedSha),
                "reproduction instructions must anchor to S0: " + dossier.reproductionInstructions());

        assertNotNull(dossier.attributionNote());
        assertTrue(dossier.attributionNote().contains("g-a") && dossier.attributionNote().contains("g-b"),
                "the attribution note must name the whole accepted set, not isolate one group: "
                        + dossier.attributionNote());

        // Each accepted group's own group-state.json is stamped with the cohort-level outcome.
        GroupStateJsonReader groupStateReader = new GroupStateJsonReader();
        for (String unitIdForGroup : List.of(
                RunPaths.unitId("critical", "com.example", "artifact-a"),
                RunPaths.unitId("high", "com.example", "artifact-b"))) {
            Path groupStatePath = runsRoot().resolve(RUN_ID).resolve("units").resolve(unitIdForGroup)
                    .resolve("group-state.json");
            assertTrue(Files.exists(groupStatePath), "group-state.json must exist for " + unitIdForGroup);
            GroupState state = groupStateReader.read(groupStatePath);
            assertEquals(GroupFinalOutcomeKind.BLOCKED_BY_COHORT_INTEGRATION_FAILURE, state.finalOutcome().kind());
            assertEquals(1, state.implementationAttempts().size(), "the group's own attempt history must be "
                    + "preserved, not lost by the later patch");
        }

        // The rendered Human Review report contains the cohort-level facts.
        Path humanReviewReportPath = runsRoot().resolve(RUN_ID).resolve("units").resolve(unitId)
                .resolve("human-review").resolve("attempt-1").resolve("human-review-report.json");
        HumanReviewReport humanReviewReport = MAPPER.readValue(
                Files.readString(humanReviewReportPath, StandardCharsets.UTF_8), HumanReviewReport.class);
        String rendered = new HumanReviewReportMarkdownRenderer().render(humanReviewReport, null, dossier);
        assertTrue(rendered.contains("g-a") && rendered.contains("g-b"), rendered);
        // Heading text updated by the decision-first renderer redesign (stage 10) -- the underlying
        // invariant (the cohort-level facts are rendered, never attributed to one specific group) is
        // unchanged, just under a new title/section structure.
        assertTrue(rendered.contains("Cohort publication blocked"), rendered);
    }
}
