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
import com.tungsten.depbot.git.RemediationChangeCommitter;
import com.tungsten.depbot.git.RemediationDiffPolicy;
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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fast, targeted regression tests for the risky-but-attemptable group path: a group requiring risky
 * routing -- {@code HUMAN_REVIEW_REQUIRED}, or legacy {@code AUTOMATION_BLOCKED} (treated identically) --
 * with a real, establishable plan (score, safety verdict and source ref all present) is attempted through
 * the exact same {@code attemptGroup} pipeline any {@code AUTOMATIC_ALLOWED} group uses, but always alone
 * in its own isolated singleton cohort -- never combined with any other group, and never a hard stop.
 */
class RiskyGroupRemediationTest {

    private static final String RUN_ID = "run1";
    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-01-01T10:00:00Z"), ZoneOffset.UTC);
    private static final String SOURCE_REF = "refs/remotes/origin/release/9.2";

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();
    private Path repo;
    private String verifiedSha;

    @BeforeEach
    void createRepository() throws Exception {
        repo = GitTestRepos.createOriginAndSingleBranchClone(tempDir, "release/9.2");
        verifiedSha = GitTestRepos.shaOf(tempDir.resolve("origin.git"), "refs/heads/release/9.2");
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

    private static String affectedFileFor(String artifactId) {
        return artifactId + ".txt";
    }

    /**
     * One finding + one group per {@code (coordinates, groupId)} pair, with a REAL {@code impactScore}/
     * {@code sourceRef} present regardless of {@code automationSafety} -- exactly the "risky-eligible"
     * shape ({@code hasImpactScore()}/{@code hasAutomationSafety()}/{@code hasSourceRef()} all true) so the
     * only variable under test is the {@code automationSafety} value itself. Carries a concrete,
     * machine-unverifiable {@code OTHER} plannedChange naming its own affected file -- {@code OTHER} alone
     * already forces {@code requiresRiskyRouting()} true, which is harmless here since every scenario in
     * this file is already risky via {@code automationSafety} too.
     */
    private static String analysisJson(String automationSafety, String[]... coordinatesAndGroupIds) {
        StringBuilder findings = new StringBuilder();
        StringBuilder groups = new StringBuilder();
        for (int i = 0; i < coordinatesAndGroupIds.length; i++) {
            String coordinates = coordinatesAndGroupIds[i][0];
            String groupId = coordinatesAndGroupIds[i][1];
            String artifactId = coordinates.substring(coordinates.indexOf(':') + 1);
            String affectedFile = affectedFileFor(artifactId);
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
                      "affectedFiles": ["%s"],
                      "impactScore": 2,
                      "impactReason": "small change",
                      "automationSafety": "%s",
                      "automationSafetyReason": "a coordinated dependency requires a human to authorise it",
                      "implementationPlan": ["raise the version"],
                      "validationPlan": ["run dependency:tree"],
                      "plannedChanges": [
                        {
                          "dependencyCoordinates": "%s",
                          "currentVersion": "1.0",
                          "targetVersion": "1.1",
                          "affectedFile": "%s",
                          "changeType": "OTHER",
                          "reason": "requires editing %s directly to close the CVE, no mechanical version bump"
                        }
                      ]
                    }""".formatted(groupId, coordinates, affectedFile, automationSafety, coordinates, affectedFile,
                    affectedFile));
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

    @Test
    @DisplayName("a HUMAN_REVIEW_REQUIRED group with a real plan is genuinely attempted -- IMPLEMENTATION "
            + "actually runs, unlike a hard skip")
    void riskyGroupGetsGenuinelyAttempted() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(Assessments.answerContaining(
                        analysisJson("HUMAN_REVIEW_REQUIRED", new String[] {"com.example:artifact-a", "g-a"}))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .creatingFileOnInvocation(2, affectedFileFor("artifact-a"), "content-a\n")
                .build();

        service(fake, new FakeJenkinsClient()).remediateAll(RUN_ID, List.of(a));

        assertEquals(List.of("assessment", "implementation"),
                fake.recordedPhaseSequence(),
                "a risky-but-attemptable group must reach a real implementation attempt, "
                        + "not be skipped straight to Human Review");

        CohortsIndex.Entry entry = cohortsIndex().cohorts().get(0);
        assertEquals(RemediationCohort.CohortKind.RISKY_SINGLE_GROUP, entry.effectiveKind());
        String expectedRiskyBranch = RemediationBranchName.forRiskyGroup(RUN_ID, SOURCE_REF, verifiedSha, "g-a");
        assertEquals(expectedRiskyBranch, entry.branchName());
        assertNotEquals(RemediationBranchName.forRun(RUN_ID, SOURCE_REF, verifiedSha), entry.branchName(),
                "a risky group's branch must never collide with the ordinary cohort branch name for the "
                        + "same (ref, sha)");
    }

    @Test
    @DisplayName("two risky groups sharing the same (ref, sha) never share a branch")
    void twoRiskyGroupsNeverShareABranch() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        VulnerabilityWorkItem b = workItem("artifact-b", "HIGH");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(Assessments.answerContaining(
                        analysisJson("HUMAN_REVIEW_REQUIRED",
                                new String[] {"com.example:artifact-a", "g-a"},
                                new String[] {"com.example:artifact-b", "g-b"}))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .creatingFileOnInvocation(2, affectedFileFor("artifact-a"), "content-a\n")
                .creatingFileOnInvocation(3, affectedFileFor("artifact-b"), "content-b\n")
                .build();

        service(fake, new FakeJenkinsClient()).remediateAll(RUN_ID, List.of(a, b));

        List<String> branches = cohortsIndex().cohorts().stream().map(CohortsIndex.Entry::branchName).toList();
        assertEquals(2, branches.size(), branches.toString());
        assertNotEquals(branches.get(0), branches.get(1), "each risky group must land on its own branch");
        assertTrue(branches.contains(RemediationBranchName.forRiskyGroup(RUN_ID, SOURCE_REF, verifiedSha, "g-a")));
        assertTrue(branches.contains(RemediationBranchName.forRiskyGroup(RUN_ID, SOURCE_REF, verifiedSha, "g-b")));
    }

    @Test
    @DisplayName("a risky group that ultimately fails both attempts goes to Human Review, exactly like an "
            + "ordinary automatic group's own exhausted repair loop")
    void riskyGroupFailureGoesToHumanReviewLikeOrdinaryGroup() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(Assessments.answerContaining(
                        analysisJson("HUMAN_REVIEW_REQUIRED", new String[] {"com.example:artifact-a", "g-a"}))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(Implementations.blockedJson()))
                .respondingTo(ClaudePhase.HUMAN_REVIEW, Assessments.claudeOutput(
                        Assessments.answerContaining(humanReviewJson())))
                .build();

        service(fake, new FakeJenkinsClient()).remediateAll(RUN_ID, List.of(a));

        assertTrue(cohortsIndex().cohorts().isEmpty(),
                "a risky group that never produced a usable commit must never be marked ready to publish");
        assertTrue(fake.recordedPhaseSequence().contains("human-review"),
                "the exhausted repair loop must still route to a real Human Review call");
    }

    @Test
    @DisplayName("a legacy AUTOMATION_BLOCKED group is treated identically to HUMAN_REVIEW_REQUIRED -- it is "
            + "genuinely attempted through the risky singleton path, never hard-stopped")
    void legacyAutomationBlockedGroupIsAttemptedLikeHumanReviewRequired() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(Assessments.answerContaining(
                        analysisJson("AUTOMATION_BLOCKED", new String[] {"com.example:artifact-a", "g-a"}))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .creatingFileOnInvocation(2, affectedFileFor("artifact-a"), "content-a\n")
                .build();

        service(fake, new FakeJenkinsClient()).remediateAll(RUN_ID, List.of(a));

        assertEquals(List.of("assessment", "implementation"), fake.recordedPhaseSequence(),
                "a legacy AUTOMATION_BLOCKED group must reach a real implementation attempt, never be "
                        + "hard-stopped, since it is now treated identically to HUMAN_REVIEW_REQUIRED");
        CohortsIndex.Entry entry = cohortsIndex().cohorts().get(0);
        assertEquals(RemediationCohort.CohortKind.RISKY_SINGLE_GROUP, entry.effectiveKind());
    }
}
