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
import com.tungsten.depbot.git.GitCommandException;
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
import com.tungsten.depbot.git.RemediationChangeCommitter;
import com.tungsten.depbot.git.RemediationDiffPolicy;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fast, targeted regression tests for the progressive-cumulative orchestration in
 * {@link VulnerabilityRemediationService#runCohort}/{@code attemptGroup} -- the two-role scheme, where
 * attempt 1 runs the Remediation Engineer directly against the Vulnerability Analysis Engineer's own
 * plan, and a failure triggers one repair attempt by the same Remediation Engineer, never a separate
 * planning role. Real temporary git repositories and {@link FakeClaude}/{@link FakeJenkinsClient}, no
 * real Maven, no real Jenkins polling, no network, no sleeps -- each test runs in well under a second.
 * Covers: cumulative chaining (a group's candidate is always cut from the previous group's own accepted
 * commit, never S0 again); a rejected group never disturbs the accepted tip or the final branch, and the
 * next group still starts from it; the accept-gate's local stages (dependency validation, full build)
 * each independently reject a candidate before cumulative Jenkins is ever triggered for it; an
 * unverifiable post-rejection rollback stops the whole cohort rather than continuing; a malformed
 * candidate (not exactly one direct child of the accepted tip) is rejected regardless of what every other
 * check said.
 */
class CumulativeRemediationTest {

    private static final String RUN_ID = "run1";
    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-01-01T10:00:00Z"), ZoneOffset.UTC);
    private static final String SOURCE_REF = "refs/remotes/origin/release/9.2";

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
        return service(fake, jenkinsClient, git);
    }

    private VulnerabilityRemediationService service(
            FakeClaude fake, FakeJenkinsClient jenkinsClient, GitCommandRunner orchestratorGit) {
        return service(fake, jenkinsClient, orchestratorGit, Implementations.passingGate(), Implementations.passingBuildGate());
    }

    private VulnerabilityRemediationService service(
            FakeClaude fake, FakeJenkinsClient jenkinsClient, GitCommandRunner orchestratorGit,
            RemediationValidationGate validationGate, FullBuildValidationGate fullBuildGate) {
        ClaudeConfig config = new ClaudeConfig(fake.executable().toString(), "opus", 20, Duration.ofSeconds(60));
        RemediationRunService runService = new RemediationRunService(FIXED_CLOCK, runsRoot());
        ClaudeCodeExecutor executor = new ClaudeCodeExecutor(config, new ClaudeProcessRunner(), runService, FIXED_CLOCK);
        JenkinsConfig jenkinsConfig = new JenkinsConfig("https://jenkins.example.invalid", "job", "user", "token",
                Duration.ofSeconds(60), Duration.ofMillis(10));

        return new VulnerabilityRemediationService(
                repo,
                orchestratorGit,
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

    /** A distinct, deterministic pom.xml path per coordinate, each in its own subdirectory -- {@code
     * PlanConformanceGate} discovers a POM by its exact filename ("pom.xml"), matching real Maven
     * convention, so each coordinate needs its own directory rather than a same-directory name variant. */
    private static String pomPathFor(String artifactId) {
        return artifactId + "/pom.xml";
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

    /**
     * One finding + one AUTOMATIC_ALLOWED group per {@code (coordinates, groupId)} pair, on {@link #SOURCE_REF}
     * -- each carrying a real, verifiable {@code VERSION_BUMP} plannedChange against its own dedicated
     * POM-like file, so {@code PlanConformanceGate} finds it conformant and {@code requiresRiskyRouting()}
     * stays {@code false}: this file's own purpose is to prove cumulative branch/commit sequencing, not
     * plan-conformance precision (that lives in its own dedicated {@code PlanConformanceGateTest}).
     */
    private static String analysisJson(String[]... coordinatesAndGroupIds) {
        StringBuilder findings = new StringBuilder();
        StringBuilder groups = new StringBuilder();
        for (int i = 0; i < coordinatesAndGroupIds.length; i++) {
            String coordinates = coordinatesAndGroupIds[i][0];
            String groupId = coordinatesAndGroupIds[i][1];
            String artifactId = coordinates.substring(coordinates.indexOf(':') + 1);
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
                    }""".formatted(groupId, coordinates, pomPathFor(artifactId), coordinates, pomPathFor(artifactId)));
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

    private String parentOf(String commitSha) throws Exception {
        return GitTestRepos.readOutput(repo, "git", "rev-parse", commitSha + "^").strip();
    }

    private List<String> commitsAheadOfS0() throws Exception {
        String output = GitTestRepos.readOutput(repo, "git", "log", "--format=%H",
                expectedBranch, "--not", verifiedSha);
        return output.lines().filter(line -> !line.isBlank()).map(String::strip).toList();
    }

    private CohortsIndex cohortsIndex() {
        return new CohortsIndexJsonReader().read(
                runsRoot().resolve(RUN_ID).resolve(CohortsIndexJsonReader.FILE_NAME));
    }

    // ---- 1. A success -> B's candidate is cut from, and commits directly on top of, A's own commit ----

    @Test
    @DisplayName("group B's candidate starts from group A's own accepted commit, not S0 again")
    void groupBStartsFromGroupACommit() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        VulnerabilityWorkItem b = workItem("artifact-b", "HIGH");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(Assessments.answerContaining(
                        analysisJson(new String[] {"com.example:artifact-a", "g-a"},
                                new String[] {"com.example:artifact-b", "g-b"}))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .creatingFileOnInvocation(2, pomPathFor("artifact-a"), pomWithVersion("artifact-a", "1.1"))
                .creatingFileOnInvocation(3, pomPathFor("artifact-b"), pomWithVersion("artifact-b", "1.1"))
                .build();

        service(fake, new FakeJenkinsClient()).remediateAll(RUN_ID, List.of(a, b));

        List<String> commits = commitsAheadOfS0();
        assertEquals(2, commits.size(), commits.toString());
        String commitB = commits.get(0);
        String commitA = commits.get(1);
        assertEquals(commitA, parentOf(commitB), "B must be a direct child of A's own commit, not of S0 again");
        assertEquals(verifiedSha, parentOf(commitA), "A must be a direct child of S0");
    }

    // ---- 2. A success -> B rejected -> C starts from A, B is absent from the final branch ----

    @Test
    @DisplayName("a rejected group never enters the final branch; the next group still starts from the last accepted tip")
    void rejectedGroupNeverEntersFinalBranchNextGroupStartsFromLastAccepted() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        VulnerabilityWorkItem b = workItem("artifact-b", "HIGH");
        VulnerabilityWorkItem c = workItem("artifact-c", "HIGH");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(Assessments.answerContaining(
                        analysisJson(new String[] {"com.example:artifact-a", "g-a"},
                                new String[] {"com.example:artifact-b", "g-b"},
                                new String[] {"com.example:artifact-c", "g-c"}))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .respondingTo(ClaudePhase.HUMAN_REVIEW, Assessments.claudeOutput(
                        Assessments.answerContaining(humanReviewJson())))
                .creatingFileOnInvocation(2, pomPathFor("artifact-a"), pomWithVersion("artifact-a", "1.1"))
                .creatingFileOnInvocation(3, pomPathFor("artifact-b"), pomWithVersion("artifact-b", "1.1"))
                .creatingFileOnInvocation(4, pomPathFor("artifact-b"), pomWithVersion("artifact-b", "1.1"))
                .creatingFileOnInvocation(6, pomPathFor("artifact-c"), pomWithVersion("artifact-c", "1.1"))
                .build();

        // Jenkins call counter counts triggerBuild+waitForCompletion together, starting at 1: group A is
        // calls 1-2. Group B's attempt 1 is calls 3-4 (fail 4); its repair attempt 2 is calls 5-6 -- also
        // failed (6), so B is genuinely, permanently rejected rather than accepted via repair. Group C is
        // calls 7-8, left to succeed normally.
        FakeJenkinsClient jenkins = new FakeJenkinsClient();
        jenkins.respondOnCallNumber(4, new JenkinsBuildResult(
                JenkinsValidationStatus.FAILED, 2, "https://jenkins.example.invalid/job/x/2/", 10L,
                "Jenkins reported result FAILURE"));
        jenkins.respondOnCallNumber(6, new JenkinsBuildResult(
                JenkinsValidationStatus.FAILED, 3, "https://jenkins.example.invalid/job/x/3/", 10L,
                "Jenkins reported result FAILURE"));

        service(fake, jenkins).remediateAll(RUN_ID, List.of(a, b, c));

        List<String> commits = commitsAheadOfS0();
        assertEquals(2, commits.size(), "only A and C, never B (rejected on both its initial and repair "
                + "attempt): " + commits);
        String commitC = commits.get(0);
        String commitA = commits.get(1);
        assertEquals(commitA, parentOf(commitC), "C must start from A's commit -- B never moved the accepted tip");
        assertThrows(AssertionError.class,
                () -> GitTestRepos.readOutput(repo, "git", "cat-file", "-e", commitC + ":" + pomPathFor("artifact-b")),
                "B's own file must never appear in the final branch's tree at all");
    }

    // ---- 3. A/B/C all succeed -> final branch has exactly one commit per group, in execution order ----

    @Test
    @DisplayName("three successful groups produce exactly one commit each, chained in execution order")
    void allThreeGroupsProduceExactlyOneCommitEachInOrder() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        VulnerabilityWorkItem b = workItem("artifact-b", "HIGH");
        VulnerabilityWorkItem c = workItem("artifact-c", "HIGH");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(Assessments.answerContaining(
                        analysisJson(new String[] {"com.example:artifact-a", "g-a"},
                                new String[] {"com.example:artifact-b", "g-b"},
                                new String[] {"com.example:artifact-c", "g-c"}))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .creatingFileOnInvocation(2, pomPathFor("artifact-a"), pomWithVersion("artifact-a", "1.1"))
                .creatingFileOnInvocation(3, pomPathFor("artifact-b"), pomWithVersion("artifact-b", "1.1"))
                .creatingFileOnInvocation(4, pomPathFor("artifact-c"), pomWithVersion("artifact-c", "1.1"))
                .build();

        service(fake, new FakeJenkinsClient()).remediateAll(RUN_ID, List.of(a, b, c));

        List<String> commits = commitsAheadOfS0();
        assertEquals(3, commits.size(), commits.toString());
        String commitC = commits.get(0);
        String commitB = commits.get(1);
        String commitA = commits.get(2);
        assertEquals(commitB, parentOf(commitC), "C must chain directly onto B");
        assertEquals(commitA, parentOf(commitB), "B must chain directly onto A");
        assertEquals(verifiedSha, parentOf(commitA), "A must chain directly onto S0");

        CohortsIndex.Entry entry = cohortsIndex().cohorts().get(0);
        assertEquals(RemediationCohort.PublicationStatus.READY_TO_PUBLISH, entry.publicationStatus());
        assertEquals(3, entry.commits().size());
        assertEquals(List.of("g-a", "g-b", "g-c"),
                entry.commits().stream().map(CohortsIndex.Commit::groupId).toList());
    }

    // ---- 4. Rollback safety cannot be verified -> remaining groups do not run, cohort cannot publish ----

    @Test
    @DisplayName("an unverifiable post-rejection rollback stops the cohort and blocks automatic publication")
    void unverifiableRollbackStopsCohortAndBlocksPublication() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        VulnerabilityWorkItem b = workItem("artifact-b", "HIGH");
        VulnerabilityWorkItem c = workItem("artifact-c", "HIGH");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(Assessments.answerContaining(
                        analysisJson(new String[] {"com.example:artifact-a", "g-a"},
                                new String[] {"com.example:artifact-b", "g-b"},
                                new String[] {"com.example:artifact-c", "g-c"}))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .respondingTo(ClaudePhase.HUMAN_REVIEW, Assessments.claudeOutput(
                        Assessments.answerContaining(humanReviewJson())))
                .creatingFileOnInvocation(2, pomPathFor("artifact-a"), pomWithVersion("artifact-a", "1.1"))
                .creatingFileOnInvocation(3, pomPathFor("artifact-b"), pomWithVersion("artifact-b", "1.1"))
                .build();

        FakeJenkinsClient jenkins = new FakeJenkinsClient();
        jenkins.respondOnCallNumber(4, new JenkinsBuildResult(
                JenkinsValidationStatus.FAILED, 2, "https://jenkins.example.invalid/job/x/2/", 10L,
                "Jenkins reported result FAILURE"));

        // Simulates the one failure mode that makes a post-rejection revert unverifiable: the candidate
        // branch for the rejected group ("g-b") cannot be deleted during cleanup.
        GitCommandRunner unreliableGit = new GitCommandRunner() {
            @Override
            public void deleteBranch(Path repoDirectory, String branchName) {
                if (branchName.contains("g-b")) {
                    throw new GitCommandException("simulated: cannot delete " + branchName);
                }
                super.deleteBranch(repoDirectory, branchName);
            }
        };

        FakeClaude spy = fake;
        service(spy, jenkins, unreliableGit).remediateAll(RUN_ID, List.of(a, b, c));

        assertEquals(5, spy.invocationCount(),
                "assessment, impl(A), impl(B) attempt 1, human-review(B's rejection), "
                        + "human-review(unsafe state) -- B's repair attempt and group C's implementation must "
                        + "never run");

        List<String> commits = commitsAheadOfS0();
        assertEquals(1, commits.size(), "A's already-accepted commit must remain untouched: " + commits);

        assertTrue(cohortsIndex().cohorts().isEmpty(),
                "a cohort that hit an unverifiable rollback must never be marked ready to publish");
    }

    // ---- 5. A malformed candidate (not exactly one direct child of the accepted tip) is rejected ----

    @Test
    @DisplayName("a candidate that is not exactly one direct child of the accepted tip is rejected, branch unchanged")
    void malformedCandidateIsRejectedCumulativeBranchUnchanged() throws Exception {
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
                .creatingFileOnInvocation(2, pomPathFor("artifact-a"), pomWithVersion("artifact-a", "1.1"))
                .creatingFileOnInvocation(3, pomPathFor("artifact-a"), pomWithVersion("artifact-a", "1.1"))
                .creatingFileOnInvocation(5, pomPathFor("artifact-b"), pomWithVersion("artifact-b", "1.1"))
                .build();

        // The production check itself (GitCommandRunner.isDirectChild) is real; only its verdict for
        // group A's candidate is forced to false here, simulating "not exactly one new descendant
        // commit" without needing to fight RemediationChangeCommitter's own reconciliation (which
        // already makes that shape unreachable through any normal Claude behavior). Since MALFORMED_COMMIT
        // is now a repairable failure stage, BOTH of A's isDirectChild checks (its initial attempt and
        // its repair attempt) are forced false, so A is genuinely, permanently rejected across both
        // attempts, exactly like this test always intended -- only B's own (real, third) check is left
        // to the genuine implementation.
        GitCommandRunner rejectFirstTwoCandidates = new GitCommandRunner() {
            private int calls = 0;

            @Override
            public boolean isDirectChild(Path repoDirectory, String candidateSha, String parentSha) {
                calls++;
                return calls > 2 && super.isDirectChild(repoDirectory, candidateSha, parentSha);
            }
        };

        service(fake, new FakeJenkinsClient(), rejectFirstTwoCandidates).remediateAll(RUN_ID, List.of(a, b));

        List<String> commits = commitsAheadOfS0();
        assertEquals(1, commits.size(), "only B; A's malformed candidate must never reach the branch: " + commits);
        String commitB = commits.get(0);
        assertEquals(verifiedSha, parentOf(commitB),
                "B must chain directly onto S0 -- A's rejected candidate must not appear as its parent");
        assertThrows(AssertionError.class,
                () -> GitTestRepos.readOutput(repo, "git", "cat-file", "-e", commitB + ":" + pomPathFor("artifact-a")),
                "A's own file must never appear in the final branch's tree at all");
        assertFalse(cohortsIndex().cohorts().isEmpty(), "B's own successful commit must still be publishable");
    }

    // ---- 6. the full build failing rejects a committed candidate before it ever reaches Jenkins -------

    @Test
    @DisplayName("a full build failure rejects an already-committed candidate before it ever reaches Jenkins")
    void acceptGateRejectsACommitWhoseFullBuildFailedEvenThoughItWasCommitted() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(Assessments.answerContaining(
                        analysisJson(new String[] {"com.example:artifact-a", "g-a"}))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .respondingTo(ClaudePhase.HUMAN_REVIEW, Assessments.claudeOutput(
                        Assessments.answerContaining(humanReviewJson())))
                .creatingFileOnInvocation(2, pomPathFor("artifact-a"), pomWithVersion("artifact-a", "1.1"))
                .build();

        FakeJenkinsClient jenkins = new FakeJenkinsClient();
        service(fake, jenkins, git, Implementations.passingGate(),
                Implementations.failingBuildGate("full build failed")).remediateAll(RUN_ID, List.of(a));

        assertEquals(0, jenkins.triggerCount(),
                "the full build already failed locally -- a candidate that never passed it must never reach Jenkins");
        // The only group in this cohort was rejected, so nothing was ever accepted -- the shared cohort
        // branch itself is deleted (never left as an empty placeholder) and no cohort is published.
        assertFalse(git.branchExistsLocally(repo, expectedBranch),
                "a cohort where nothing was accepted must not leave a shared branch behind");
        assertFalse(git.branchExistsLocally(repo,
                        RemediationBranchName.forGroupCandidate(RUN_ID, SOURCE_REF, verifiedSha, "g-a")),
                "the rejected candidate branch must be deleted, not left behind");
        assertTrue(cohortsIndex().cohorts().isEmpty(), "a cohort with zero accepted groups must never publish");
    }

    // ---- 7. dependency validation failing rejects a candidate before it ever reaches Jenkins ----------

    @Test
    @DisplayName("a dependency-validation failure rejects a candidate before it ever reaches Jenkins")
    void dependencyValidationFailureIsRejectedBeforeCumulativeJenkins() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(Assessments.answerContaining(
                        analysisJson(new String[] {"com.example:artifact-a", "g-a"}))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .respondingTo(ClaudePhase.HUMAN_REVIEW, Assessments.claudeOutput(
                        Assessments.answerContaining(humanReviewJson())))
                .creatingFileOnInvocation(2, pomPathFor("artifact-a"), pomWithVersion("artifact-a", "1.1"))
                .build();

        FakeJenkinsClient jenkins = new FakeJenkinsClient();
        service(fake, jenkins, git, Implementations.failingGate("1.1 does not resolve offline"),
                Implementations.passingBuildGate()).remediateAll(RUN_ID, List.of(a));

        assertEquals(0, jenkins.triggerCount(),
                "dependency validation already failed locally -- Jenkins must never be triggered for this candidate");
        assertFalse(git.branchExistsLocally(repo, expectedBranch),
                "a cohort where nothing was accepted must not leave a shared branch behind");
        assertFalse(git.branchExistsLocally(repo,
                        RemediationBranchName.forGroupCandidate(RUN_ID, SOURCE_REF, verifiedSha, "g-a")),
                "the rejected candidate branch must be deleted, not left behind");
        assertTrue(cohortsIndex().cohorts().isEmpty(), "a cohort with zero accepted groups must never publish");
    }

    // ---- 8. the post-rejection rollback is verified before the next group's implementation ever runs --

    @Test
    @DisplayName("the post-rejection rollback is fully verified before the next group's own implementation "
            + "attempt is ever started")
    void rollbackIsExplicitlyVerifiedBeforeTheNextGroupRuns() throws Exception {
        VulnerabilityWorkItem a = workItem("artifact-a", "CRITICAL");
        VulnerabilityWorkItem b = workItem("artifact-b", "HIGH");
        VulnerabilityWorkItem c = workItem("artifact-c", "HIGH");
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(Assessments.answerContaining(
                        analysisJson(new String[] {"com.example:artifact-a", "g-a"},
                                new String[] {"com.example:artifact-b", "g-b"},
                                new String[] {"com.example:artifact-c", "g-c"}))))
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(
                        Assessments.answerContaining(Implementations.completedJson())))
                .respondingTo(ClaudePhase.HUMAN_REVIEW, Assessments.claudeOutput(
                        Assessments.answerContaining(humanReviewJson())))
                .creatingFileOnInvocation(2, pomPathFor("artifact-a"), pomWithVersion("artifact-a", "1.1"))
                .creatingFileOnInvocation(3, pomPathFor("artifact-b"), pomWithVersion("artifact-b", "1.1"))
                .creatingFileOnInvocation(4, pomPathFor("artifact-b"), pomWithVersion("artifact-b", "1.1"))
                .creatingFileOnInvocation(6, pomPathFor("artifact-c"), pomWithVersion("artifact-c", "1.1"))
                .build();

        // Group A: calls 1-2. Group B's attempt 1: calls 3-4 (fail 4); its repair attempt 2: calls 5-6
        // (also failed, so B is genuinely rejected on both attempts -- two revert events to observe, not
        // one). Group C: calls 7-8, succeeds normally.
        FakeJenkinsClient jenkins = new FakeJenkinsClient();
        jenkins.respondOnCallNumber(4, new JenkinsBuildResult(
                JenkinsValidationStatus.FAILED, 2, "https://jenkins.example.invalid/job/x/2/", 10L,
                "Jenkins reported result FAILURE"));
        jenkins.respondOnCallNumber(6, new JenkinsBuildResult(
                JenkinsValidationStatus.FAILED, 3, "https://jenkins.example.invalid/job/x/3/", 10L,
                "Jenkins reported result FAILURE"));

        // Captured every instant production code deletes one of B's (rejected) candidate branches -- the
        // last action `safelyRevertToAccepted` takes -- proving the four-part verification it performs
        // (HEAD/branch-ref/clean-tree/no-leftover-branch) already held at that exact moment. B now goes
        // through this twice (once discarding attempt 1 before the repair attempt, once discarding attempt
        // 2 on final rejection) -- both attempts' candidate branches share the same name, so both deletes
        // match "g-b"; what matters is that the LAST one -- immediately before group C ever starts --
        // is fully verified.
        record RevertSnapshot(String headSha, boolean clean, String branchRefSha, int phaseCountSoFar) {
        }
        List<RevertSnapshot> snapshots = new java.util.ArrayList<>();
        GitCommandRunner observingGit = new GitCommandRunner() {
            @Override
            public void deleteBranch(Path repoDirectory, String branchName) {
                if (branchName.contains("g-b")) {
                    try {
                        snapshots.add(new RevertSnapshot(
                                currentHeadSha(repoDirectory),
                                isClean(repoDirectory),
                                revParseCommit(repoDirectory, "refs/heads/" + expectedBranch),
                                fake.recordedPhaseSequence().size()));
                    } catch (java.io.IOException e) {
                        throw new java.io.UncheckedIOException(e);
                    }
                }
                super.deleteBranch(repoDirectory, branchName);
            }
        };

        service(fake, jenkins, observingGit).remediateAll(RUN_ID, List.of(a, b, c));

        assertEquals(2, snapshots.size(),
                "B's candidate branch must be deleted twice -- once discarding attempt 1 before the repair "
                        + "attempt, once on attempt 2's own final rejection");
        RevertSnapshot snapshot = snapshots.get(snapshots.size() - 1);
        String commitA = commitsAheadOfS0().get(commitsAheadOfS0().size() - 1);
        assertEquals(commitA, snapshot.headSha(),
                "HEAD must already be back at A's accepted tip during B's own FINAL revert");
        assertTrue(snapshot.clean(), "the working tree must already be clean during B's own final revert");
        assertEquals(commitA, snapshot.branchRefSha(),
                "the shared branch ref must already point at A's accepted tip during B's own final revert");

        List<String> fullSequence = fake.recordedPhaseSequence();
        assertTrue(fullSequence.size() > snapshot.phaseCountSoFar(),
                "group C must still run its own implementation call after B's revert");
        assertEquals("implementation", fullSequence.get(snapshot.phaseCountSoFar()),
                "the very next Claude call recorded after B's verified revert must be C's own Remediation "
                        + "Engineer call, never anything that could have started before the revert was verified");
    }
}
