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
import com.tungsten.depbot.implementation.PlanConformanceResult;
import com.tungsten.depbot.validation.RemediationValidationGate;
import com.tungsten.depbot.validation.ValidationOutcome;
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
        return service(fake, jenkinsClient, Implementations.passingGate());
    }

    private VulnerabilityRemediationService service(
            FakeClaude fake, FakeJenkinsClient jenkinsClient,
            com.tungsten.depbot.validation.RemediationValidationGate dependencyGate) {
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
                        dependencyGate, Implementations.passingBuildGate()),
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

    /** As {@link #analysisJson(String, String)}, but the group is classified {@code EXTENDED} -- run
     *  20260919-221201-636b49's implementationBudget fix: an EXTENDED group may reach a third attempt,
     *  each at the EXTENDED turn/timeout budget, when the first two both fail. */
    private static String analysisJsonExtended(String coordinates, String groupId) {
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
                      "recommendedRemediation": "migrate to the new major version",
                      "recommendedTargetVersion": "1.1",
                      "affectedFiles": ["pom.xml"],
                      "impactScore": 8,
                      "impactReason": "a real migration across a major API boundary",
                      "automationSafety": "AUTOMATIC_ALLOWED",
                      "automationSafetyReason": "no coordinated dependency is involved",
                      "implementationPlan": ["migrate to the new major version"],
                      "validationPlan": ["run dependency:tree"],
                      "implementationBudget": "EXTENDED",
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

    // ---- implementationBudget: EXTENDED groups may reach a third attempt (run 20260919-221201-636b49) ----

    @Test
    @DisplayName("an EXTENDED group reaches a third attempt when the first two both fail -- a STANDARD "
            + "group never would (see rejectedOnBothAttemptsProducesFullDossierAndNoCommit above)")
    void extendedGroupReachesThirdAttemptAfterTwoFailures() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(
                        Assessments.answerContaining(analysisJsonExtended("com.example:artifact-a", "g-a"))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .creatingFileOnInvocation(2, "pom.xml", pomWithVersion("artifact-a", "1.1"))
                .creatingFileOnInvocation(3, "pom.xml", pomWithVersion("artifact-a", "1.1"))
                .creatingFileOnInvocation(4, "pom.xml", pomWithVersion("artifact-a", "1.1"))
                .build();

        // Attempt 1's pair is calls 1-2 (fail call 2); attempt 2's pair is calls 3-4 (fail call 4);
        // attempt 3's pair (calls 5-6) falls through to the default canned SUCCESS result.
        FakeJenkinsClient jenkins = new FakeJenkinsClient();
        jenkins.respondOnCallNumber(2, new JenkinsBuildResult(
                JenkinsValidationStatus.FAILED, 2, "https://jenkins.example.invalid/job/x/2/", 10L,
                "Jenkins reported result FAILURE"));
        jenkins.respondOnCallNumber(4, new JenkinsBuildResult(
                JenkinsValidationStatus.FAILED, 4, "https://jenkins.example.invalid/job/x/4/", 10L,
                "Jenkins reported result FAILURE"));

        List<VulnerabilityRemediationOutcome> outcomes = service(fake, jenkins).remediateAll(RUN_ID, List.of(a));

        List<String> commits = commitsAheadOfS0();
        assertEquals(1, commits.size(),
                "exactly one commit -- attempts 1 and 2's own candidates were discarded: " + commits);
        assertEquals(verifiedSha, parentOf(commits.get(0)),
                "attempt 3 must be cut fresh from acceptedTip (S0), never stacked on a failed commit");

        assertEquals(1, outcomes.size());
        assertTrue(outcomes.get(0).committed());

        List<String> phases = fake.recordedPhaseSequence();
        assertEquals(3, phases.stream().filter(p -> p.equals("implementation")).count(),
                "an EXTENDED group may reach three implementation attempts when the first two both fail, "
                        + "unlike a STANDARD group's hard two-attempt limit");

        String unitId = RunPaths.unitId("critical", "com.example", "artifact-a");
        Path unitDirectory = runsRoot().resolve(RUN_ID).resolve("units").resolve(unitId).resolve("implementation");
        assertTrue(Files.exists(unitDirectory.resolve("attempt-1").resolve("prompt.md")));
        assertTrue(Files.exists(unitDirectory.resolve("attempt-2").resolve("prompt.md")));
        assertTrue(Files.exists(unitDirectory.resolve("attempt-3").resolve("prompt.md")),
                "the third, EXTENDED-only attempt must have its own artifact directory, never overwriting "
                        + "the first two");

        GroupState groupState = new GroupStateJsonReader().read(
                runsRoot().resolve(RUN_ID).resolve("units").resolve(unitId).resolve("group-state.json"));
        assertEquals(3, groupState.implementationAttempts().size(),
                "the audit trail must carry all three attempts for an EXTENDED group");
    }

    // ---- Bug 1 (run 20260920-031107-148632): a companion-file exclusion added in direct response to a
    // ---- real DEPENDENCY_VALIDATION failure is accepted as a narrow scope extension, not rejected as an
    // ---- unauthorized file change -----------------------------------------------------------------------

    private static final String JSON_LIB_COORDINATES = "net.sf.json-lib:json-lib";

    private static VulnerabilityWorkItem jsonLibWorkItem() {
        var library = Assessments.library("net.sf.json-lib", "json-lib", "2.4");
        return new VulnerabilityWorkItem("net.sf.json-lib", "json-lib", "2.4", "CRITICAL", "2.4",
                List.of(Assessments.finding("CVE-2026-JSONLIB", "critical",
                        library, "Exclude net.sf.json-lib:json-lib")));
    }

    private static String jsonLibAnalysisJson() {
        return """
                {
                  "schemaVersion": "1.0",
                  "findings": [
                    {
                      "coordinates": "net.sf.json-lib:json-lib",
                      "vulnerabilityIds": ["CVE-2026-JSONLIB"],
                      "summary": "needs remediation",
                      "conclusion": "REMEDIATION_REQUIRED",
                      "remediationGroupId": "g-jsonlib",
                      "evidence": ["evidence"]
                    }
                  ],
                  "remediationGroups": [
                    {
                      "groupId": "g-jsonlib",
                      "memberCoordinates": ["net.sf.json-lib:json-lib"],
                      "groupingReason": "a single, unrelated finding",
                      "sourceRef": "origin/release/9.2",
                      "sourceCommitSha": "0123456789abcdef0123456789abcdef01234567",
                      "origin": "TRANSITIVE",
                      "dependencyRelationship": "arrives transitively",
                      "observedVersion": "2.4",
                      "recommendedRemediation": "exclude the vulnerable transitive dependency",
                      "recommendedTargetVersion": "2.4",
                      "affectedFiles": ["pom.xml"],
                      "impactScore": 2,
                      "impactReason": "small change",
                      "automationSafety": "AUTOMATIC_ALLOWED",
                      "automationSafetyReason": "a narrow exclusion is sufficient",
                      "implementationPlan": ["exclude net.sf.json-lib:json-lib in pom.xml"],
                      "validationPlan": ["run dependency:tree"],
                      "plannedChanges": [
                        {
                          "dependencyCoordinates": "com.example:webapp-core",
                          "currentVersion": null,
                          "targetVersion": null,
                          "affectedFile": "pom.xml",
                          "changeType": "EXCLUSION_ADDED",
                          "excludedCoordinates": ["net.sf.json-lib:json-lib"],
                          "reason": "excludes the vulnerable transitive dependency from webapp-core"
                        }
                      ]
                    }
                  ]
                }
                """;
    }

    /** The root pom's own, plan-authorized exclusion -- present from attempt 1 onward, unrelated to the
     *  companion module's own, separate transitive path. */
    private static String rootPomWithJsonLibExcluded() {
        return """
                <project>
                  <dependencies>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>webapp-core</artifactId>
                      <version>1.0</version>
                      <exclusions>
                        <exclusion>
                          <groupId>net.sf.json-lib</groupId>
                          <artifactId>json-lib</artifactId>
                        </exclusion>
                      </exclusions>
                    </dependency>
                  </dependencies>
                </project>
                """;
    }

    /** The companion module's pom, as it exists at baseline -- pulling in json-lib transitively, with no
     *  exclusion of its own yet. */
    private static String testServicesPomBaseline() {
        return """
                <project>
                  <dependencies>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>jaxbjsonsdo</artifactId>
                      <version>2.2</version>
                    </dependency>
                  </dependencies>
                </project>
                """;
    }

    /** As {@link #testServicesPomBaseline()}, but with attempt 2's own, narrow exclusion added --
     *  structurally identical otherwise. */
    private static String testServicesPomWithJsonLibExcluded() {
        return """
                <project>
                  <dependencies>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>jaxbjsonsdo</artifactId>
                      <version>2.2</version>
                      <exclusions>
                        <exclusion>
                          <groupId>net.sf.json-lib</groupId>
                          <artifactId>json-lib</artifactId>
                        </exclusion>
                      </exclusions>
                    </dependency>
                  </dependencies>
                </project>
                """;
    }

    /** Adds {@code test-services/pom.xml} (see {@link #testServicesPomBaseline()}) to the {@code
     *  release/9.2} baseline itself, and refreshes {@link #verifiedSha}/{@link #expectedBranch} to the new
     *  tip -- so the companion module genuinely already existed before either implementation attempt ran,
     *  exactly like the real run this test reproduces. */
    private void addTestServicesModuleToBaseline() throws Exception {
        GitTestRepos.run(repo, "git", "fetch", "-q", "origin", "release/9.2:refs/remotes/origin/release/9.2");
        GitTestRepos.run(repo, "git", "checkout", "-q", "-B", "release/9.2", "refs/remotes/origin/release/9.2");
        Path testServicesDir = repo.resolve("test-services");
        Files.createDirectories(testServicesDir);
        Files.writeString(testServicesDir.resolve("pom.xml"), testServicesPomBaseline(), StandardCharsets.UTF_8);
        GitTestRepos.run(repo, "git", "add", "test-services/pom.xml");
        GitTestRepos.run(repo, "git", "commit", "-q", "-m", "add test-services module");
        GitTestRepos.run(repo, "git", "push", "-q", "origin", "HEAD:release/9.2");
        GitTestRepos.run(repo, "git", "checkout", "-q", "master");
        verifiedSha = GitTestRepos.shaOf(tempDir.resolve("origin.git"), "refs/heads/release/9.2");
        expectedBranch = RemediationBranchName.forRun(RUN_ID, SOURCE_REF, verifiedSha);
    }

    /** A dependency-validation gate driven purely by whether {@code test-services/pom.xml} has, by now,
     *  gained its own exclusion for {@code net.sf.json-lib:json-lib} -- standing in for the real Maven
     *  dependency-resolution gate, whose verdict in the actual run this test reproduces depended on exactly
     *  that fact. */
    private static RemediationValidationGate testServicesExclusionRequiredGate() {
        return request -> {
            Path testServicesPom = request.workspace().resolve("test-services").resolve("pom.xml");
            if (Files.exists(testServicesPom)) {
                try {
                    String content = Files.readString(testServicesPom, StandardCharsets.UTF_8);
                    if (content.contains("<exclusion>") && content.contains("json-lib")) {
                        return ValidationOutcome.passed(
                                "net.sf.json-lib:json-lib no longer resolves on the classpath",
                                List.of("mvn", "-o", "-B", "dependency:tree"), "stub output");
                    }
                } catch (java.io.IOException e) {
                    throw new java.io.UncheckedIOException(e);
                }
            }
            return ValidationOutcome.failed(
                    "TestServices -> jaxbjsonsdo:2.2 -> net.sf.json-lib:json-lib:2.4 remained on the "
                            + "resolved classpath",
                    List.of("mvn", "-o", "-B", "dependency:tree"), "stub output");
        };
    }

    @Test
    @DisplayName("attempt 1's real DEPENDENCY_VALIDATION failure lets attempt 2's own, narrow exclusion in "
            + "an existing companion pom.xml be accepted as a scope extension -- not rejected as an "
            + "unauthorized file change -- and the group is still routed to human review despite conforming")
    void companionFileExclusionAfterDependencyValidationFailureIsAcceptedAsScopeExtension() throws Exception {
        addTestServicesModuleToBaseline();

        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(
                        Assessments.answerContaining(jsonLibAnalysisJson())))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .creatingFileOnInvocation(2, "pom.xml", rootPomWithJsonLibExcluded())
                .creatingFileOnInvocation(3, "pom.xml", rootPomWithJsonLibExcluded())
                .creatingFileOnInvocation(3, "test-services/pom.xml", testServicesPomWithJsonLibExcluded())
                .build();

        FakeJenkinsClient jenkins = new FakeJenkinsClient();

        List<VulnerabilityRemediationOutcome> outcomes = service(fake, jenkins, testServicesExclusionRequiredGate())
                .remediateAll(RUN_ID, List.of(jsonLibWorkItem()));

        assertEquals(1, outcomes.size());
        assertTrue(outcomes.get(0).committed(),
                "attempt 2's own exclusion in the companion file must let the dependency-validation gate "
                        + "pass and the change be committed, not rejected as an unauthorized file change");

        List<String> phases = fake.recordedPhaseSequence();
        assertEquals(2, phases.stream().filter(p -> p.equals("implementation")).count(),
                "exactly two implementation attempts -- attempt 1's real DEPENDENCY_VALIDATION failure, "
                        + "then attempt 2's accepted repair");

        String unitId = RunPaths.unitId("critical", "net.sf.json-lib", "json-lib");
        Path attempt2Directory = runsRoot().resolve(RUN_ID).resolve("units").resolve(unitId)
                .resolve("implementation").resolve("attempt-2");
        PlanConformanceResult planConformance = MAPPER.readValue(
                Files.readString(attempt2Directory.resolve(RemediationImplementationService.PLAN_CONFORMANCE_FILE),
                        StandardCharsets.UTF_8),
                PlanConformanceResult.class);

        assertTrue(planConformance.conformant(),
                "the companion file's own exclusion-only change must not be scored as a violation: "
                        + planConformance.violations());
        assertTrue(planConformance.violations().isEmpty(), planConformance.violations().toString());
        assertTrue(planConformance.scopeExtensions().stream().anyMatch(e -> e.contains("test-services/pom.xml")),
                "the accepted extension must name the companion file it authorized: "
                        + planConformance.scopeExtensions());

        GroupState groupState = new GroupStateJsonReader().read(
                runsRoot().resolve(RUN_ID).resolve("units").resolve(unitId).resolve("group-state.json"));
        assertEquals(GroupFinalOutcomeKind.ACCEPTED_RISKY, groupState.finalOutcome().kind(),
                "a scope-extended success must still be routed to human review despite conforming, never "
                        + "treated as an ordinary, unconditionally auto-mergeable acceptance");
    }
}
