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
 * Fast regression tests for the build-failure repair loop: a Jenkins failure on implementation attempt 1
 * triggers a separate repair planning cycle (revising the existing plan, never investigating from
 * scratch) followed by implementation attempt 2 -- the FINAL attempt, either way. Real temporary git
 * repositories and {@link FakeClaude}/{@link FakeJenkinsClient}, no real Maven, no real Jenkins polling,
 * no network.
 */
class RepairLoopIntegrationTest {

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

    private List<String> commitsAheadOfS0() throws Exception {
        String output = GitTestRepos.readOutput(repo, "git", "log", "--format=%H", expectedBranch, "--not", verifiedSha);
        return output.lines().filter(line -> !line.isBlank()).map(String::strip).toList();
    }

    private String parentOf(String commitSha) throws Exception {
        return GitTestRepos.readOutput(repo, "git", "rev-parse", commitSha + "^").strip();
    }

    private CohortsIndex cohortsIndex() {
        return new CohortsIndexJsonReader().read(
                runsRoot().resolve(RUN_ID).resolve(CohortsIndexJsonReader.FILE_NAME));
    }

    private RejectedGroupOutcome readRejectedGroupOutcome(String unitId) throws Exception {
        Path path = runsRoot().resolve(RUN_ID).resolve("units").resolve(unitId)
                .resolve("human-review").resolve("attempt-1").resolve("rejected-group-outcome.json");
        return MAPPER.readValue(Files.readString(path, StandardCharsets.UTF_8), RejectedGroupOutcome.class);
    }

    @Test
    @DisplayName("a Jenkins failure on attempt 1 triggers a repair cycle; attempt 2 (cut fresh from "
            + "acceptedTip) succeeds and becomes the group's one and only commit")
    void jenkinsFailureOnAttempt1TriggersRepairThenAttempt2Succeeds() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(
                        Assessments.answerContaining(analysisJson("com.example:artifact-a", "g-a"))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .creatingFileOnInvocation(2, "pom.xml", pomWithVersion("artifact-a", "1.1"))
                .creatingFileOnInvocation(3, "pom.xml", pomWithVersion("artifact-a", "1.1"))
                .build();

        // FakeJenkinsClient's own callCount increments on BOTH triggerBuild and waitForCompletion, and
        // respondOnCallNumber's lookup happens inside waitForCompletion AFTER its own increment -- so
        // the relevant call number for the Nth trigger+wait pair is 2N (2, 4, 6...), not N. Attempt 1's
        // pair is calls 1-2 -- fail call 2, its own waitForCompletion.
        FakeJenkinsClient jenkins = new FakeJenkinsClient();
        jenkins.respondOnCallNumber(2, new JenkinsBuildResult(
                JenkinsValidationStatus.FAILED, 2, "https://jenkins.example.invalid/job/x/2/", 10L,
                "Jenkins reported result FAILURE"));
        // attempt 2's own pair (calls 3-4) falls through to the default canned SUCCESS result.

        List<VulnerabilityRemediationOutcome> outcomes = service(fake, jenkins).remediateAll(RUN_ID, List.of(a));

        List<String> commits = commitsAheadOfS0();
        assertEquals(1, commits.size(), "exactly one commit -- attempt 1's own candidate was discarded: " + commits);
        assertEquals(verifiedSha, parentOf(commits.get(0)),
                "attempt 2 must be cut fresh from acceptedTip (S0), never stacked on attempt 1's failed commit");

        CohortsIndex index = cohortsIndex();
        assertFalse(index.cohorts().isEmpty());
        assertEquals(1, index.cohorts().get(0).commits().size());

        assertEquals(1, outcomes.size());
        assertTrue(outcomes.get(0).committed());

        // Exactly one repair attempt ever ran: IMPLEMENTATION appears twice in the phase sequence
        // (attempt 1, then the repair attempt), never three times.
        List<String> phases = fake.recordedPhaseSequence();
        assertEquals(2, phases.stream().filter(p -> p.equals("implementation")).count(),
                "exactly two implementation attempts -- initial and repair, never a third");

        // attempt-1 and attempt-2 are distinct, independent directories -- attempt 2 never overwrites
        // attempt 1's own evidence. Both must exist side by side once the run has finished.
        Path unitDirectory = runsRoot().resolve(RUN_ID)
                .resolve("units").resolve(RunPaths.unitId("critical", "com.example", "artifact-a"))
                .resolve("implementation");
        Path attempt1Prompt = unitDirectory.resolve("attempt-1").resolve("prompt.md");
        Path repairPrompt = unitDirectory.resolve("attempt-2").resolve("prompt.md");
        assertTrue(Files.exists(attempt1Prompt), "attempt 1's own prompt must still exist, untouched");
        assertTrue(Files.exists(repairPrompt), "the repair attempt's own prompt must exist, in its own directory");

        // attempt 1's own prompt is the ordinary, non-repair prompt -- proof attempt 2 never overwrote it.
        String initialPrompt = Files.readString(attempt1Prompt, StandardCharsets.UTF_8);
        assertFalse(initialPrompt.contains("This is a repair attempt"),
                "attempt 1's own prompt must never contain repair evidence: " + initialPrompt);

        // The repair attempt's own prompt actually contains the group's plan and the Jenkins failure
        // evidence, with an explicit don't-re-investigate instruction.
        String prompt = Files.readString(repairPrompt, StandardCharsets.UTF_8);
        assertTrue(prompt.contains("raise the version"),
                "the repair prompt must reproduce the group's own recommended remediation: " + prompt);
        assertTrue(prompt.contains("This is a repair attempt"), prompt);
        assertTrue(prompt.contains("cumulative Jenkins validation failed"),
                "the repair prompt must reproduce the exact Jenkins failure evidence: " + prompt);
    }

    @Test
    @DisplayName("a group rejected on both the initial and the repair attempt produces no commit, a "
            + "non-null applicablePatch, and a dossier carrying both planning cycles")
    void rejectedOnBothAttemptsProducesFullDossierAndNoCommit() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(
                        Assessments.answerContaining(analysisJson("com.example:artifact-a", "g-a"))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .respondingTo(ClaudePhase.HUMAN_REVIEW, Assessments.claudeOutput(
                        Assessments.answerContaining(humanReviewJson())))
                .creatingFileOnInvocation(2, "pom.xml", pomWithVersion("artifact-a", "1.1"))
                .creatingFileOnInvocation(3, "pom.xml", pomWithVersion("artifact-a", "1.1"))
                .build();

        FakeJenkinsClient jenkins = new FakeJenkinsClient();
        jenkins.respondWith(new JenkinsBuildResult(
                JenkinsValidationStatus.FAILED, 2, "https://jenkins.example.invalid/job/x/2/", 10L,
                "Jenkins reported result FAILURE"));

        List<VulnerabilityRemediationOutcome> outcomes = service(fake, jenkins).remediateAll(RUN_ID, List.of(a));

        // A single-group cohort where the only group was rejected on both attempts has zero accepted
        // candidates -- the shared branch itself is deleted entirely (never left as an empty
        // placeholder), so asserting "no commits ahead of S0" would fail with "unknown revision" rather
        // than proving anything; the branch's absence is the actual invariant to check.
        assertFalse(git.branchExistsLocally(repo, expectedBranch),
                "a cohort where nothing was accepted must not leave a shared branch behind");
        assertTrue(cohortsIndex().cohorts().isEmpty());

        assertEquals(1, outcomes.size());
        assertFalse(outcomes.get(0).committed());
        assertTrue(outcomes.get(0).humanReviewOutcome() != null && outcomes.get(0).humanReviewOutcome().hasReport());

        RejectedGroupOutcome dossier = readRejectedGroupOutcome(RunPaths.unitId("critical", "com.example", "artifact-a"));
        assertEquals(RejectionStage.CUMULATIVE_JENKINS, dossier.stoppedAtStage());
        assertNotNull(dossier.applicablePatch(), "attempt 2's own patch must be captured before it was discarded");
        assertTrue(dossier.applicablePatch().contains("artifact-a"), dossier.applicablePatch());

        // Both attempts' own artifact directories must independently survive a double failure -- neither
        // overwrites the other -- so the evidence behind the final Human Review dossier is recoverable
        // for both attempts, not just the last one.
        String unitId = RunPaths.unitId("critical", "com.example", "artifact-a");
        Path unitDirectory = runsRoot().resolve(RUN_ID).resolve("units").resolve(unitId).resolve("implementation");
        Path attempt1Json = unitDirectory.resolve("attempt-1")
                .resolve(RemediationImplementationService.ATTEMPT_FILE);
        Path attempt2Json = unitDirectory.resolve("attempt-2")
                .resolve(RemediationImplementationService.ATTEMPT_FILE);
        assertTrue(Files.exists(attempt1Json), "attempt 1's own implementation-attempt.json must survive");
        assertTrue(Files.exists(attempt2Json), "attempt 2's own implementation-attempt.json must exist "
                + "in its own directory, never overwriting attempt 1's");

        GroupState groupState = new GroupStateJsonReader().read(
                runsRoot().resolve(RUN_ID).resolve("units").resolve(unitId).resolve("group-state.json"));
        assertEquals(2, groupState.implementationAttempts().size(),
                "the audit trail must carry both attempts, not collapse them into one");
        List<String> artifactPaths = groupState.implementationAttempts().stream()
                .map(GroupState.ImplementationAttemptState::implementationArtifactPath)
                .toList();
        assertEquals(2, artifactPaths.stream().distinct().count(),
                "each attempt's own artifact path must be distinct, so the Human Review dossier's evidence "
                        + "trail can reference either attempt independently: " + artifactPaths);
    }
}
