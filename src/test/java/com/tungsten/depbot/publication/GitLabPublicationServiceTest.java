package com.tungsten.depbot.publication;

import com.tungsten.depbot.assessment.AssessmentConclusion;
import com.tungsten.depbot.assessment.AutomationSafety;
import com.tungsten.depbot.assessment.RemediationVerdict;
import com.tungsten.depbot.claude.ClaudeRunOutcome;
import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.git.GitTestRepos;
import com.tungsten.depbot.git.RefsRefreshOutcome;
import com.tungsten.depbot.git.RestoreOutcome;
import com.tungsten.depbot.humanreview.HumanReviewJsonRenderer;
import com.tungsten.depbot.humanreview.HumanReviewOutcome;
import com.tungsten.depbot.humanreview.HumanReviewReport;
import com.tungsten.depbot.humanreview.HumanReviewService;
import com.tungsten.depbot.implementation.ImplementationConclusion;
import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;
import com.tungsten.depbot.jenkins.JenkinsValidationStatus;
import com.tungsten.depbot.remediation.CohortsIndex;
import com.tungsten.depbot.remediation.RejectedGroupOutcome;
import com.tungsten.depbot.remediation.RejectedGroupOutcomeJsonRenderer;
import com.tungsten.depbot.remediation.RejectionStage;
import com.tungsten.depbot.remediation.RemediationCohort;
import com.tungsten.depbot.remediation.RemediationReport;
import com.tungsten.depbot.remediation.RemediationReportJsonRenderer;
import com.tungsten.depbot.remediation.RemediationStage;
import com.tungsten.depbot.remediation.RemediationSummary;
import com.tungsten.depbot.remediation.RemediationSummaryBuilder;
import com.tungsten.depbot.remediation.VulnerabilityRemediationOutcome;
import com.tungsten.depbot.run.RemediationRunService;
import com.tungsten.depbot.validation.ValidationStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The publication layer against a real git repository and an in-memory GitLab -- proving the branch is
 * genuinely pushed, one Merge Request covers the whole cohort, every commit's own report reaches GitLab
 * against its exact SHA, one Issue covers a whole Human Review group (never one per library inside it), a
 * retried publish neither duplicates anything nor loses what already succeeded, and a Merge Request a
 * human has already closed or merged is never reopened, recreated, or pushed to again.
 *
 * <p>{@link RemoteIdentityVerifier} is replaced with an always-succeeding stub in every test here except
 * the ones specifically about identity mismatch -- the real check is covered by {@link
 * RemoteIdentityVerifierTest}, and every fixture repository's own {@code origin} remote is a local
 * filesystem path, not a real GitLab host, so the real verifier would always refuse it.
 */
class GitLabPublicationServiceTest {

    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-08-16T10:00:00Z"), ZoneOffset.UTC);
    private static final String RUN_ID = "run1";
    private static final String VERIFIED_REF = "refs/remotes/origin/hotfix-2026.1";
    private static final String VERIFIED_SHA = "3473b0daa6be8017e6235f2e7ddba88f967f1309";
    private static final ClaudeRunOutcome CLEAN_CALL =
            new ClaudeRunOutcome(true, 0, false, null, List.of("claude"), "start", "finish");

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();
    private Path repo;
    private RemediationRunService runService;
    private FakeGitLabClient gitLabClient;
    private GitLabPublicationService service;

    @BeforeEach
    void setUp() throws Exception {
        repo = GitTestRepos.createOriginAndClone(tempDir);
        runService = new RemediationRunService(FIXED_CLOCK, tempDir.resolve("reports").resolve("runs"));
        gitLabClient = new FakeGitLabClient();
        service = serviceWithGit(git);
    }

    private GitLabPublicationService serviceWithGit(GitCommandRunner gitCommandRunner) {
        GitLabConfig config = new GitLabConfig(
                "https://gitlab.example.invalid", "123", "token-not-logged", "origin");
        return new GitLabPublicationService(repo, gitCommandRunner, config, gitLabClient, runService,
                new RemediationReportMarkdownRenderer(), new HumanReviewReportMarkdownRenderer(),
                new PublicationSummaryMarkdownRenderer(), new PublicationIndexJsonRenderer(),
                new AlwaysVerifiedIdentityVerifier());
    }

    /** Never touches git or GitLab -- every other test here needs identity verification out of the way. */
    private static final class AlwaysVerifiedIdentityVerifier extends RemoteIdentityVerifier {
        @Override
        public VerificationResult verify(
                GitCommandRunner git, Path repoPath, String remoteName, GitLabClient client, GitLabConfig config) {
            return VerificationResult.success();
        }
    }

    /** Counts real {@code git push} invocations -- the literal proof a rejected/skipped path never pushes. */
    private static final class CountingPushGitCommandRunner extends GitCommandRunner {
        private int pushCount = 0;

        @Override
        public void push(Path repoDirectory, String remote, String branchName) {
            pushCount++;
            super.push(repoDirectory, remote, branchName);
        }

        int pushCount() {
            return pushCount;
        }
    }

    /** Creates a branch with one real commit, exactly what the remediation orchestrator leaves behind. */
    private String commitOnNewBranch(String branchName, String fileName, String content) throws Exception {
        git.createBranch(repo, branchName, git.currentHeadSha(repo));
        git.checkout(repo, branchName);
        Files.writeString(repo.resolve(fileName), content, StandardCharsets.UTF_8);
        GitTestRepos.run(repo, "git", "add", "-A");
        GitTestRepos.run(repo, "git", "commit", "-q", "-m", "remediate: " + fileName);
        String sha = git.currentHeadSha(repo);
        git.checkout(repo, "master");
        return sha;
    }

    private Path writeRemediationReport(String unitId, RemediationReport report) throws Exception {
        Path directory = runService.unitDirectoryFor(RUN_ID, unitId).resolve("implementation").resolve("attempt-1");
        Files.createDirectories(directory);
        Path path = directory.resolve("remediation-report.json");
        Files.writeString(path, new RemediationReportJsonRenderer().render(report), StandardCharsets.UTF_8);
        return path;
    }

    private Path humanReviewDirectoryFor(String unitId) {
        return runService.unitDirectoryFor(RUN_ID, unitId).resolve("human-review").resolve("attempt-1");
    }

    private void writeHumanReviewReport(String unitId, HumanReviewReport report) throws Exception {
        Path directory = humanReviewDirectoryFor(unitId);
        Files.createDirectories(directory);
        Files.writeString(directory.resolve(HumanReviewService.REPORT_FILE),
                new HumanReviewJsonRenderer().render(report), StandardCharsets.UTF_8);
    }

    /** Writes a sibling {@code rejected-group-outcome.json} next to an already-written Human Review report. */
    private void writeRejectedGroupOutcome(String unitId, RejectedGroupOutcome outcome) throws Exception {
        Path directory = humanReviewDirectoryFor(unitId);
        Files.createDirectories(directory);
        Files.writeString(directory.resolve("rejected-group-outcome.json"),
                new RejectedGroupOutcomeJsonRenderer().render(outcome), StandardCharsets.UTF_8);
    }

    private static RejectedGroupOutcome httpComponentsRejectedGroupOutcome() {
        return new RejectedGroupOutcome(
                "1.0", "g-httpcomponents5-family", "HIGH", 1,
                List.of("org.apache.httpcomponents.core5:httpcore5", "org.apache.httpcomponents.client5:httpclient5"),
                "acceptedBaseShaXYZ", RejectionStage.CUMULATIVE_JENKINS,
                "raised the httpcomponents5 family to 5.4.1", List.of("pom.xml"),
                ImplementationConclusion.COMPLETED, ValidationStatus.PASSED, ValidationStatus.PASSED,
                null, "the final cumulative Jenkins build failed after the coordinated bump", true,
                "acceptedBaseShaXYZ", true, List.of(), List.of(), null, null, null, null);
    }

    private static JenkinsValidationOutcome jenkinsSuccess(String candidateSha) {
        return new JenkinsValidationOutcome(JenkinsValidationStatus.SUCCESS, "WebApplicationDependencyValidation",
                1, "http://jenkins.example/job/x/1/", VERIFIED_SHA, candidateSha, "treesha", 42L,
                "Jenkins reported result SUCCESS");
    }

    private static RemediationReport mchangeReport(String commitSha) {
        return new RemediationReport("1.0", commitSha, "g-mchange",
                List.of("com.mchange:c3p0", "com.mchange:mchange-commons-java"),
                "raised c3p0 and mchange-commons-java to their fixed versions", "coordinated CVE fix",
                "the analysis recommended a coordinated bump", List.of("pom.xml"),
                "Dependency-resolution gate: PASSED", List.of(
                        new RemediationReport.VersionChange("com.mchange:c3p0", "0.13.0", "0.14.0"),
                        new RemediationReport.VersionChange("com.mchange:mchange-commons-java", "0.5.0", "0.6.0")),
                ValidationStatus.PASSED, ValidationStatus.PASSED,
                jenkinsSuccess(commitSha), jenkinsSuccess(commitSha));
    }

    private static HumanReviewReport httpComponentsReport() {
        return new HumanReviewReport("1.0",
                "org.apache.httpcomponents.core5:httpcore5, org.apache.httpcomponents.client5:httpclient5",
                "the httpcomponents5 family carries a request-smuggling CVE", "a connection-pool flaw",
                "declared directly in the root pom", "raise the whole family to 5.4.1 together",
                List.of("org.apache.httpcomponents.core5:httpcore5-h2"), "run the integration suite",
                List.of(), List.of("a coordinated multi-artifact bump carries more risk than a single one"),
                null, null);
    }

    /** Two members of the same Claude-defined group, sharing one Human Review directory and report. */
    private VulnerabilityRemediationOutcome[] humanReviewGroupOutcomes(String unitId) {
        HumanReviewOutcome shared = new HumanReviewOutcome(
                RUN_ID, unitId, "httpcomponents5-family", httpComponentsReport(), CLEAN_CALL,
                humanReviewDirectoryFor(unitId), null);
        VulnerabilityRemediationOutcome first = new VulnerabilityRemediationOutcome(
                RUN_ID, "high__org.apache.httpcomponents.core5__httpcore5",
                "org.apache.httpcomponents.core5:httpcore5", RefsRefreshOutcome.refreshed("origin"),
                AssessmentConclusion.REMEDIATION_REQUIRED, RemediationVerdict.HUMAN_REVIEW_REQUIRED,
                "needs a human", null, null, AutomationSafety.HUMAN_REVIEW_REQUIRED,
                "runtime-sensitive coordinated bump", null, null, null, null, shared,
                RestoreOutcome.success(), RemediationStage.HUMAN_REVIEW, "needs a human");
        VulnerabilityRemediationOutcome second = new VulnerabilityRemediationOutcome(
                RUN_ID, "high__org.apache.httpcomponents.client5__httpclient5",
                "org.apache.httpcomponents.client5:httpclient5", RefsRefreshOutcome.refreshed("origin"),
                AssessmentConclusion.REMEDIATION_REQUIRED, RemediationVerdict.HUMAN_REVIEW_REQUIRED,
                "needs a human", null, null, AutomationSafety.HUMAN_REVIEW_REQUIRED,
                "runtime-sensitive coordinated bump", null, null, null, null, shared,
                RestoreOutcome.success(), RemediationStage.HUMAN_REVIEW, "needs a human");
        return new VulnerabilityRemediationOutcome[] {first, second};
    }

    private RemediationSummary summaryWithHumanReviewGroup(String unitId) {
        return RemediationSummaryBuilder.build(RUN_ID, "2026-08-16T10:00:00Z", "opus", repo.toString(), null,
                List.of(humanReviewGroupOutcomes(unitId)));
    }

    private RemediationSummary emptySummary() {
        return RemediationSummaryBuilder.build(RUN_ID, "2026-08-16T10:00:00Z", "opus", repo.toString(), null, List.of());
    }

    // ---- the happy path, unchanged in spirit from before eligibility/preflight/discovery existed -------

    @Test
    @DisplayName("publishing an eligible cohort pushes its branch for real, opens one Merge Request, and "
            + "posts the commit's own report against its exact SHA")
    void publishesCohortBranchMergeRequestAndCommitReport() throws Exception {
        String branchName = "remediation/run1/hotfix-2026.1-3473b0daa6be";
        String commitSha = commitOnNewBranch(branchName, "pom.xml", "<project><version>0.14.0</version></project>\n");
        Path reportPath = writeRemediationReport("high__group__g-mchange", mchangeReport(commitSha));

        CohortsIndex cohortsIndex = new CohortsIndex(RUN_ID, List.of(new CohortsIndex.Entry(
                branchName, VERIFIED_REF, VERIFIED_SHA, RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-mchange", commitSha, reportPath.toString())))));

        PublicationIndex index = service.publish(RUN_ID, cohortsIndex, emptySummary());

        assertEquals(commitSha, GitTestRepos.shaOf(tempDir.resolve("origin.git"), "refs/heads/" + branchName));
        assertEquals(1, gitLabClient.mergeRequestCount());
        assertEquals("hotfix-2026.1", gitLabClient.mergeRequestTargetBranch(1));

        List<String> comments = gitLabClient.commitComments(commitSha);
        assertEquals(1, comments.size());
        assertTrue(comments.get(0).contains("g-mchange"), comments.get(0));
        assertTrue(comments.get(0).contains("0.14.0"), comments.get(0));
        assertTrue(comments.get(0).contains("Full application build after this commit"), comments.get(0));

        assertEquals(1, index.cohorts().size());
        PublicationIndex.CohortPublication cohortPublication = index.cohorts().get(0);
        assertEquals(RemediationCohort.PublicationStatus.MERGE_REQUEST_OPENED, cohortPublication.status());
        assertEquals(1, cohortPublication.publishedCommits().size());
        assertTrue(cohortPublication.publishedCommits().get(0).reportPublished());

        String description = gitLabClient.mergeRequestDescription(1);
        assertTrue(description.contains("1 remediation group"), description);
        assertTrue(description.contains("2 libraries updated"), description);
        assertTrue(description.contains("1 commit created"), description);

        assertTrue(Files.exists(runService.runDirectoryFor(RUN_ID).resolve(GitLabPublicationService.PUBLICATION_FILE)));
    }

    @Test
    @DisplayName("a RISKY_SINGLE_GROUP cohort's Merge Request title carries a [Risky] prefix an ordinary "
            + "cohort's does not")
    void riskySingleGroupCohortGetsRiskyTitlePrefix() throws Exception {
        String branchName = "remediation/run1/hotfix-2026.1-3473b0daa6be-risky/g-mchange";
        String commitSha = commitOnNewBranch(branchName, "pom.xml", "<project><version>0.14.0</version></project>\n");
        Path reportPath = writeRemediationReport("high__group__g-mchange", mchangeReport(commitSha));

        CohortsIndex cohortsIndex = new CohortsIndex(RUN_ID, List.of(new CohortsIndex.Entry(
                branchName, VERIFIED_REF, VERIFIED_SHA, RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-mchange", commitSha, reportPath.toString())),
                RemediationCohort.CohortKind.RISKY_SINGLE_GROUP)));

        service.publish(RUN_ID, cohortsIndex, emptySummary());

        assertEquals(1, gitLabClient.mergeRequestCount());
        assertTrue(gitLabClient.mergeRequestTitle(1).startsWith("[Risky] "), gitLabClient.mergeRequestTitle(1));
    }

    @Test
    @DisplayName("a cohort missing any bot-owned validation fact is never pushed at all")
    void ineligibleCohortIsNeverPushed() throws Exception {
        String branchName = "remediation/run1/hotfix-2026.1-3473b0daa6be";
        String commitSha = commitOnNewBranch(branchName, "pom.xml", "<project/>\n");
        // isolatedJenkinsValidation FAILED -- not eligible, even though everything else would pass.
        RemediationReport ineligible = new RemediationReport("1.0", commitSha, "g-mchange",
                List.of("com.mchange:c3p0"), "changed", "necessary", "why", List.of("pom.xml"), "validated",
                List.of(), ValidationStatus.PASSED, ValidationStatus.PASSED,
                new JenkinsValidationOutcome(JenkinsValidationStatus.FAILED, "job", 2, "url", VERIFIED_SHA,
                        commitSha, "tree", 5L, "Jenkins reported result FAILURE"),
                jenkinsSuccess(commitSha));
        Path reportPath = writeRemediationReport("high__group__g-mchange", ineligible);

        CountingPushGitCommandRunner countingGit = new CountingPushGitCommandRunner();
        GitLabPublicationService serviceUnderTest = serviceWithGit(countingGit);
        CohortsIndex cohortsIndex = new CohortsIndex(RUN_ID, List.of(new CohortsIndex.Entry(
                branchName, VERIFIED_REF, VERIFIED_SHA, RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-mchange", commitSha, reportPath.toString())))));

        PublicationIndex index = serviceUnderTest.publish(RUN_ID, cohortsIndex, emptySummary());

        assertEquals(0, countingGit.pushCount());
        assertEquals(RemediationCohort.PublicationStatus.PUBLICATION_FAILED, index.cohorts().get(0).status());
        assertTrue(index.cohorts().get(0).errorMessage().contains("Jenkins validation did not succeed"),
                index.cohorts().get(0).errorMessage());
        assertThrows(AssertionError.class,
                () -> GitTestRepos.shaOf(tempDir.resolve("origin.git"), "refs/heads/" + branchName));
    }

    @Test
    @DisplayName("a cohort whose local branch no longer matches cohorts.json's recorded tip is never pushed")
    void repositoryPreflightMismatchIsNeverPushed() throws Exception {
        String branchName = "remediation/run1/hotfix-2026.1-3473b0daa6be";
        String realCommitSha = commitOnNewBranch(branchName, "pom.xml", "<project/>\n");
        Path reportPath = writeRemediationReport("high__group__g-mchange", mchangeReport(realCommitSha));

        // cohorts.json claims a commit sha that does not exist on the branch at all.
        String fabricatedSha = "0".repeat(40);
        CountingPushGitCommandRunner countingGit = new CountingPushGitCommandRunner();
        GitLabPublicationService serviceUnderTest = serviceWithGit(countingGit);
        CohortsIndex cohortsIndex = new CohortsIndex(RUN_ID, List.of(new CohortsIndex.Entry(
                branchName, VERIFIED_REF, VERIFIED_SHA, RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-mchange", fabricatedSha, reportPath.toString())))));

        PublicationIndex index = serviceUnderTest.publish(RUN_ID, cohortsIndex, emptySummary());

        assertEquals(0, countingGit.pushCount());
        assertEquals(RemediationCohort.PublicationStatus.PUBLICATION_FAILED, index.cohorts().get(0).status());
    }

    @Test
    @DisplayName("one Human Review group with two members gets exactly one Issue, never one per library")
    void oneIssuePerHumanReviewGroupNotPerLibrary() throws Exception {
        String unitId = "high__group__httpcomponents5-family";
        writeHumanReviewReport(unitId, httpComponentsReport());
        CohortsIndex emptyCohorts = new CohortsIndex(RUN_ID, List.of());
        RemediationSummary summary = summaryWithHumanReviewGroup(unitId);

        PublicationIndex index = service.publish(RUN_ID, emptyCohorts, summary);

        assertEquals(1, gitLabClient.issueCount());
        assertTrue(gitLabClient.issueTitle(1).contains("Human review required"), gitLabClient.issueTitle(1));
        assertTrue(gitLabClient.issueTitle(1).contains("httpcore5"), gitLabClient.issueTitle(1));

        String description = gitLabClient.issueDescription(1);
        assertTrue(description.contains("Automatic code modification performed:** NO"), description);
        assertTrue(description.contains(RUN_ID), description);

        assertEquals(1, index.humanReviewGroups().size());
        assertEquals(IssuePublicationStatus.PUBLISHED, index.humanReviewGroups().get(0).status());
        assertEquals(2, index.humanReviewGroups().get(0).memberCoordinates().size());
    }

    @Test
    @DisplayName("the published Human Review Issue actually carries the rejected-group-outcome dossier, "
            + "not just the bare report -- the regression test for a dead-code gap where the dossier was "
            + "always threaded to the local human-review-report.md but never to what's actually published")
    void publishedIssueCarriesRejectedGroupOutcomeDossier() throws Exception {
        String unitId = "high__group__httpcomponents5-family";
        writeHumanReviewReport(unitId, httpComponentsReport());
        writeRejectedGroupOutcome(unitId, httpComponentsRejectedGroupOutcome());
        CohortsIndex emptyCohorts = new CohortsIndex(RUN_ID, List.of());
        RemediationSummary summary = summaryWithHumanReviewGroup(unitId);

        service.publish(RUN_ID, emptyCohorts, summary);

        String description = gitLabClient.issueDescription(1);
        assertTrue(description.contains("CUMULATIVE_JENKINS"), description);
        assertTrue(description.contains("the final cumulative Jenkins build failed after the coordinated bump"),
                description);
    }

    @Test
    @DisplayName("a retried publish neither duplicates the Merge Request, the commit report, nor the Issue")
    void retryDoesNotDuplicateAnything() throws Exception {
        String branchName = "remediation/run1/hotfix-2026.1-3473b0daa6be";
        String commitSha = commitOnNewBranch(branchName, "pom.xml", "<project/>\n");
        Path reportPath = writeRemediationReport("high__group__g-mchange", mchangeReport(commitSha));
        String humanReviewUnitId = "high__group__httpcomponents5-family";
        writeHumanReviewReport(humanReviewUnitId, httpComponentsReport());

        CohortsIndex cohortsIndex = new CohortsIndex(RUN_ID, List.of(new CohortsIndex.Entry(
                branchName, VERIFIED_REF, VERIFIED_SHA, RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-mchange", commitSha, reportPath.toString())))));
        RemediationSummary summary = summaryWithHumanReviewGroup(humanReviewUnitId);

        service.publish(RUN_ID, cohortsIndex, summary);
        service.publish(RUN_ID, cohortsIndex, summary);

        assertEquals(1, gitLabClient.mergeRequestCount(), "a retry must reuse the same Merge Request");
        assertEquals(1, gitLabClient.commitComments(commitSha).size(), "a retry must not repost the same report");
        assertEquals(1, gitLabClient.issueCount(), "a retry must reuse the same Issue");
    }

    @Test
    @DisplayName("a publication failure marks only the affected cohort as failed, keeps its local commit "
            + "untouched, and a later retry completes what failed")
    void partialFailureIsRecordedAndLaterRetryCompletes() throws Exception {
        String branchName = "remediation/run1/hotfix-2026.1-3473b0daa6be";
        String commitSha = commitOnNewBranch(branchName, "pom.xml", "<project/>\n");
        Path reportPath = writeRemediationReport("high__group__g-mchange", mchangeReport(commitSha));

        CohortsIndex cohortsIndex = new CohortsIndex(RUN_ID, List.of(new CohortsIndex.Entry(
                branchName, VERIFIED_REF, VERIFIED_SHA, RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-mchange", commitSha, reportPath.toString())))));
        RemediationSummary summary = emptySummary();

        // Call 1 is the find-merge-request lookup (not found), call 2 is creating it (succeeds), call 3
        // is the idempotency check before posting the commit's own report -- that is where it fails.
        gitLabClient.failOnCallNumber(3, new GitLabPublicationException("simulated network failure"));

        PublicationIndex firstAttempt = service.publish(RUN_ID, cohortsIndex, summary);

        assertEquals(RemediationCohort.PublicationStatus.PUBLICATION_FAILED,
                firstAttempt.cohorts().get(0).status());
        assertEquals(1, gitLabClient.mergeRequestCount(), "the Merge Request from before the failure survives");
        assertTrue(gitLabClient.commitComments(commitSha).isEmpty());
        assertEquals(commitSha, git.revParseCommit(repo, branchName));

        PublicationIndex retried = service.publish(RUN_ID, cohortsIndex, summary);

        assertEquals(RemediationCohort.PublicationStatus.MERGE_REQUEST_OPENED, retried.cohorts().get(0).status());
        assertEquals(1, gitLabClient.mergeRequestCount(), "still the same Merge Request, not a second one");
        assertEquals(1, gitLabClient.commitComments(commitSha).size());
    }

    @Test
    @DisplayName("the Human Review Issue carries the run id and the verified source ref/SHA when one was named")
    void humanReviewIssueCarriesRunIdAndVerifiedRef() throws Exception {
        String unitId = "high__group__httpcomponents5-family";
        writeHumanReviewReport(unitId, httpComponentsReport());

        HumanReviewOutcome shared = new HumanReviewOutcome(
                RUN_ID, unitId, "httpcomponents5-family", httpComponentsReport(), CLEAN_CALL,
                humanReviewDirectoryFor(unitId), null);
        VulnerabilityRemediationOutcome outcome = new VulnerabilityRemediationOutcome(
                RUN_ID, "high__org.apache.httpcomponents.core5__httpcore5",
                "org.apache.httpcomponents.core5:httpcore5", RefsRefreshOutcome.refreshed("origin"),
                AssessmentConclusion.REMEDIATION_REQUIRED, RemediationVerdict.HUMAN_REVIEW_REQUIRED,
                "needs a human", null, null, AutomationSafety.HUMAN_REVIEW_REQUIRED,
                "runtime-sensitive coordinated bump",
                com.tungsten.depbot.git.SourceRefVerification.verified(
                        "origin/hotfix-2026.1", VERIFIED_REF, VERIFIED_SHA, "claimedsha"),
                null, null, null, shared, RestoreOutcome.success(), RemediationStage.HUMAN_REVIEW, "needs a human");
        RemediationSummary summary = RemediationSummaryBuilder.build(
                RUN_ID, "2026-08-16T10:00:00Z", "opus", repo.toString(), null, List.of(outcome));

        service.publish(RUN_ID, new CohortsIndex(RUN_ID, List.of()), summary);

        String description = gitLabClient.issueDescription(1);
        assertTrue(description.contains(RUN_ID), description);
        assertTrue(description.contains(VERIFIED_REF), description);
        assertTrue(description.contains(VERIFIED_SHA), description);
    }

    // ---- backward-compatible branch naming: never recomputed for a persisted cohort --------------------

    @Test
    @DisplayName("a persisted cohort's branch name is used exactly as recorded, never recomputed -- proven "
            + "with an old-style, real-world branch name from an actual production run")
    void standalonePublishUsesThePersistedBranchNameNeverRecomputesIt() throws Exception {
        // The exact branch name persisted in a real production run's cohorts.json (run 20260821-225436-7a8e8c).
        String oldStyleBranchName = "remediation/20260821-225436-7a8e8c/refs_remotes_origin_hotfix-2026.1-3473b0daa6be";
        // A name no naming algorithm in this codebase would ever produce for this fixture's own
        // runId/ref/sha -- proves the service published under the PERSISTED name, not some freshly
        // derived one, without this test depending on any particular naming algorithm's exact output.
        String neverUsedName = "remediation/some-other-run/some-other-branch-name";
        assertNotEquals(oldStyleBranchName, neverUsedName);

        String commitSha = commitOnNewBranch(oldStyleBranchName, "pom.xml", "<project/>\n");
        Path reportPath = writeRemediationReport("critical__org.bouncycastle__bcprov-jdk18on",
                mchangeReport(commitSha));
        CohortsIndex cohortsIndex = new CohortsIndex("20260821-225436-7a8e8c", List.of(new CohortsIndex.Entry(
                oldStyleBranchName, VERIFIED_REF, VERIFIED_SHA, RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("grp-bouncycastle", commitSha, reportPath.toString())))));

        service.publish("20260821-225436-7a8e8c", cohortsIndex, emptySummary());

        assertEquals(commitSha,
                GitTestRepos.shaOf(tempDir.resolve("origin.git"), "refs/heads/" + oldStyleBranchName));
        assertThrows(AssertionError.class, () -> GitTestRepos.shaOf(
                tempDir.resolve("origin.git"), "refs/heads/" + neverUsedName));
    }

    // ---- multi-cohort preview: one run, several source refs/SHAs -----------------------------------

    @Test
    @DisplayName("preview never mutates anything, and reports every cohort separately when one run has "
            + "several -- distinct source refs, distinct branches, distinct Merge Request targets")
    void dryRunPreviewShowsEachCohortSeparatelyAndNeverMutates() throws Exception {
        String branchA = "remediation/run1/hotfix-2026.1-3473b0daa6be";
        String commitA = commitOnNewBranch(branchA, "a.txt", "a\n");
        Path reportA = writeRemediationReport("high__group__g-mchange", mchangeReport(commitA));

        String otherSha = git.revParseCommit(repo, "master");
        String branchB = "remediation/run1/release-9.2-someothersha";
        git.checkout(repo, "master");
        String commitB = commitOnNewBranch(branchB, "b.txt", "b\n");
        RemediationReport reportForB = new RemediationReport("1.0", commitB, "g-bcprov",
                List.of("org.bouncycastle:bcprov-jdk18on"), "changed", "necessary", "why", List.of("pom.xml"),
                "validated", List.of(), ValidationStatus.PASSED, ValidationStatus.PASSED,
                jenkinsSuccess(commitB), jenkinsSuccess(commitB));
        Path reportBPath = writeRemediationReport("critical__org.bouncycastle__bcprov-jdk18on", reportForB);

        CohortsIndex cohortsIndex = new CohortsIndex(RUN_ID, List.of(
                new CohortsIndex.Entry(branchA, VERIFIED_REF, VERIFIED_SHA,
                        RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                        List.of(new CohortsIndex.Commit("g-mchange", commitA, reportA.toString()))),
                new CohortsIndex.Entry(branchB, "refs/remotes/origin/release-9.2", otherSha,
                        RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                        List.of(new CohortsIndex.Commit("g-bcprov", commitB, reportBPath.toString())))));

        PublicationPreview preview = service.preview(RUN_ID, cohortsIndex, emptySummary());

        assertEquals(2, preview.cohorts().size());
        PublicationPreview.CohortPreview previewA = preview.cohorts().get(0);
        PublicationPreview.CohortPreview previewB = preview.cohorts().get(1);

        assertEquals("hotfix-2026.1", previewA.targetBranch());
        assertEquals("release-9.2", previewB.targetBranch());
        assertNotEquals(previewA.localBranch(), previewB.localBranch());
        assertNotEquals(previewA.sourceSha(), previewB.sourceSha());
        assertTrue(previewA.eligible());
        assertTrue(previewB.eligible());
        assertEquals(List.of("g-mchange"), previewA.groupIds());
        assertEquals(List.of("g-bcprov"), previewB.groupIds());
        assertEquals(commitA, previewA.expectedHeadSha());
        assertEquals(commitB, previewB.expectedHeadSha());

        // A pure preview -- no Merge Request, no push, nothing on the remote.
        assertEquals(0, gitLabClient.mergeRequestCount());
        assertThrows(AssertionError.class, () -> GitTestRepos.shaOf(tempDir.resolve("origin.git"), "refs/heads/" + branchA));
        assertThrows(AssertionError.class, () -> GitTestRepos.shaOf(tempDir.resolve("origin.git"), "refs/heads/" + branchB));
    }

    // ---- discover-before-mutate: the exact policy for each Merge Request state ------------------------

    @Test
    @DisplayName("an already-CLOSED Merge Request is discovered before any push -- the branch (even if "
            + "GitLab already deleted it) is never resurrected, never pushed to, never reopened, and the "
            + "cohort is reported MERGE_REQUEST_CLOSED, not as a failure")
    void closedMergeRequestIsNeverPushedToOrRecreated() throws Exception {
        String branchName = "remediation/run1/hotfix-2026.1-3473b0daa6be";
        String commitSha = commitOnNewBranch(branchName, "pom.xml", "<project/>\n");
        Path reportPath = writeRemediationReport("high__group__g-mchange", mchangeReport(commitSha));
        int closedIid = gitLabClient.seedMergeRequest(branchName, "hotfix-2026.1", MergeRequestState.CLOSED);

        CountingPushGitCommandRunner countingGit = new CountingPushGitCommandRunner();
        GitLabPublicationService serviceUnderTest = serviceWithGit(countingGit);
        CohortsIndex cohortsIndex = new CohortsIndex(RUN_ID, List.of(new CohortsIndex.Entry(
                branchName, VERIFIED_REF, VERIFIED_SHA, RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-mchange", commitSha, reportPath.toString())))));

        PublicationIndex index = serviceUnderTest.publish(RUN_ID, cohortsIndex, emptySummary());

        assertEquals(0, countingGit.pushCount(), "a closed Merge Request must never be pushed to");
        assertThrows(AssertionError.class, () -> GitTestRepos.shaOf(
                tempDir.resolve("origin.git"), "refs/heads/" + branchName),
                "the branch GitLab already deleted when the Merge Request was closed must never reappear");
        assertEquals(1, gitLabClient.mergeRequestCount(), "no second Merge Request is created");
        assertTrue(gitLabClient.commitComments(commitSha).isEmpty(),
                "no report is posted against a closed Merge Request either");

        PublicationIndex.CohortPublication cohort = index.cohorts().get(0);
        assertEquals(RemediationCohort.PublicationStatus.MERGE_REQUEST_CLOSED, cohort.status());
        assertEquals(closedIid, cohort.mergeRequestIid());
    }

    @Test
    @DisplayName("an already-MERGED Merge Request is discovered before any push -- the branch is never "
            + "resurrected, no new Merge Request is created, and the cohort is reported MERGED")
    void mergedMergeRequestIsNeverPushedToOrRecreated() throws Exception {
        String branchName = "remediation/run1/hotfix-2026.1-3473b0daa6be";
        String commitSha = commitOnNewBranch(branchName, "pom.xml", "<project/>\n");
        Path reportPath = writeRemediationReport("high__group__g-mchange", mchangeReport(commitSha));
        int mergedIid = gitLabClient.seedMergeRequest(branchName, "hotfix-2026.1", MergeRequestState.MERGED);

        CountingPushGitCommandRunner countingGit = new CountingPushGitCommandRunner();
        GitLabPublicationService serviceUnderTest = serviceWithGit(countingGit);
        CohortsIndex cohortsIndex = new CohortsIndex(RUN_ID, List.of(new CohortsIndex.Entry(
                branchName, VERIFIED_REF, VERIFIED_SHA, RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-mchange", commitSha, reportPath.toString())))));

        PublicationIndex index = serviceUnderTest.publish(RUN_ID, cohortsIndex, emptySummary());

        assertEquals(0, countingGit.pushCount(), "an already-merged Merge Request must never be pushed to");
        assertThrows(AssertionError.class, () -> GitTestRepos.shaOf(
                tempDir.resolve("origin.git"), "refs/heads/" + branchName));
        assertEquals(1, gitLabClient.mergeRequestCount());

        PublicationIndex.CohortPublication cohort = index.cohorts().get(0);
        assertEquals(RemediationCohort.PublicationStatus.MERGED, cohort.status());
        assertEquals(mergedIid, cohort.mergeRequestIid());
    }

    @Test
    @DisplayName("an OPEN Merge Request whose remote branch already matches the expected tip is never "
            + "pushed to again -- no duplicate Merge Request, safe continuation to the commit report")
    void openMergeRequestWithMatchingRemoteShaContinuesSafelyWithoutAnotherPush() throws Exception {
        String branchName = "remediation/run1/hotfix-2026.1-3473b0daa6be";
        String commitSha = commitOnNewBranch(branchName, "pom.xml", "<project/>\n");
        Path reportPath = writeRemediationReport("high__group__g-mchange", mchangeReport(commitSha));
        // Simulates a previous successful publish: the branch is already on the remote, and an OPEN
        // Merge Request already references it.
        git.push(repo, "origin", branchName);
        gitLabClient.seedMergeRequest(branchName, "hotfix-2026.1", MergeRequestState.OPEN);

        CountingPushGitCommandRunner countingGit = new CountingPushGitCommandRunner();
        GitLabPublicationService serviceUnderTest = serviceWithGit(countingGit);
        CohortsIndex cohortsIndex = new CohortsIndex(RUN_ID, List.of(new CohortsIndex.Entry(
                branchName, VERIFIED_REF, VERIFIED_SHA, RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-mchange", commitSha, reportPath.toString())))));

        PublicationIndex index = serviceUnderTest.publish(RUN_ID, cohortsIndex, emptySummary());

        assertEquals(0, countingGit.pushCount(),
                "an already-open Merge Request's branch is only verified, never pushed to again");
        assertEquals(1, gitLabClient.mergeRequestCount(), "no duplicate Merge Request");
        assertEquals(1, gitLabClient.commitComments(commitSha).size(), "the commit report still reaches GitLab");
        assertEquals(RemediationCohort.PublicationStatus.MERGE_REQUEST_OPENED, index.cohorts().get(0).status());
    }

    @Test
    @DisplayName("an OPEN Merge Request whose remote branch does NOT match the expected tip fails closed "
            + "-- never force-pushed, never silently reconciled")
    void openMergeRequestWithMismatchedRemoteShaFailsClosedWithoutForcePush() throws Exception {
        String branchName = "remediation/run1/hotfix-2026.1-3473b0daa6be";
        String commitSha = commitOnNewBranch(branchName, "pom.xml", "<project/>\n");
        Path reportPath = writeRemediationReport("high__group__g-mchange", mchangeReport(commitSha));
        // The remote branch exists but points at a completely different, unrelated commit -- someone
        // (or something) other than this publish changed it since the Merge Request was opened.
        String unrelatedSha = git.revParseCommit(repo, "master");
        GitTestRepos.run(repo, "git", "push", "origin", unrelatedSha + ":refs/heads/" + branchName);
        gitLabClient.seedMergeRequest(branchName, "hotfix-2026.1", MergeRequestState.OPEN);

        CountingPushGitCommandRunner countingGit = new CountingPushGitCommandRunner();
        GitLabPublicationService serviceUnderTest = serviceWithGit(countingGit);
        CohortsIndex cohortsIndex = new CohortsIndex(RUN_ID, List.of(new CohortsIndex.Entry(
                branchName, VERIFIED_REF, VERIFIED_SHA, RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-mchange", commitSha, reportPath.toString())))));

        PublicationIndex index = serviceUnderTest.publish(RUN_ID, cohortsIndex, emptySummary());

        assertEquals(0, countingGit.pushCount(), "a diverged remote branch must never be force-pushed over");
        assertEquals(unrelatedSha,
                GitTestRepos.shaOf(tempDir.resolve("origin.git"), "refs/heads/" + branchName),
                "the remote branch must be left exactly as it was found");
        assertTrue(gitLabClient.commitComments(commitSha).isEmpty(), "no report is posted when this fails closed");

        PublicationIndex.CohortPublication cohort = index.cohorts().get(0);
        assertEquals(RemediationCohort.PublicationStatus.PUBLICATION_FAILED, cohort.status());
        assertTrue(cohort.errorMessage().contains("does not match the expected tip"), cohort.errorMessage());
    }

    // ---- idempotency across closed objects, and fail-closed on ambiguous identity -----------------

    @Test
    @DisplayName("a Human Review group whose Issue already exists and is CLOSED is never duplicated -- "
            + "reported ISSUE_CLOSED, not PUBLISHED")
    void closedExistingIssueIsNeverDuplicated() throws Exception {
        String unitId = "high__group__httpcomponents5-family";
        writeHumanReviewReport(unitId, httpComponentsReport());
        RemediationSummary summary = summaryWithHumanReviewGroup(unitId);
        // The group's stable identity is its full unitId, not just the suffix after "group__" -- see
        // GitLabPublicationService#distinctHumanReviewGroups, which reads it two path segments up from
        // the human-review directory.
        String marker = "<!-- depbot-human-review:" + RUN_ID + ":" + unitId + " -->";
        int closedIid = gitLabClient.seedIssue(marker, IssueState.CLOSED);

        PublicationIndex index = service.publish(RUN_ID, new CohortsIndex(RUN_ID, List.of()), summary);

        assertEquals(1, gitLabClient.issueCount(), "no duplicate issue is created");
        assertEquals(IssuePublicationStatus.ISSUE_CLOSED, index.humanReviewGroups().get(0).status());
        assertEquals(closedIid, index.humanReviewGroups().get(0).issueIid());

        // Retrying again must still not duplicate anything.
        PublicationIndex retried = service.publish(RUN_ID, new CohortsIndex(RUN_ID, List.of()), summary);
        assertEquals(1, gitLabClient.issueCount());
        assertEquals(IssuePublicationStatus.ISSUE_CLOSED, retried.humanReviewGroups().get(0).status());
    }

    @Test
    @DisplayName("more than one Merge Request matching the same source branch fails closed rather than "
            + "guessing which one is authoritative")
    void duplicateMergeRequestMarkerFailsClosed() throws Exception {
        String branchName = "remediation/run1/hotfix-2026.1-3473b0daa6be";
        String commitSha = commitOnNewBranch(branchName, "pom.xml", "<project/>\n");
        Path reportPath = writeRemediationReport("high__group__g-mchange", mchangeReport(commitSha));
        gitLabClient.seedMergeRequest(branchName, "hotfix-2026.1", MergeRequestState.OPEN);
        gitLabClient.seedDuplicateMergeRequest(branchName, "hotfix-2026.1");

        CohortsIndex cohortsIndex = new CohortsIndex(RUN_ID, List.of(new CohortsIndex.Entry(
                branchName, VERIFIED_REF, VERIFIED_SHA, RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-mchange", commitSha, reportPath.toString())))));

        PublicationIndex index = service.publish(RUN_ID, cohortsIndex, emptySummary());

        assertEquals(RemediationCohort.PublicationStatus.PUBLICATION_FAILED, index.cohorts().get(0).status());
        assertTrue(index.cohorts().get(0).errorMessage().contains("Found 2 merge requests"),
                index.cohorts().get(0).errorMessage());
        assertEquals(2, gitLabClient.mergeRequestCount(), "no new merge request is created on top of the ambiguity");
    }

    @Test
    @DisplayName("more than one Issue matching the same stable identity marker fails closed rather than "
            + "guessing which one is authoritative")
    void duplicateIssueMarkerFailsClosed() throws Exception {
        String unitId = "high__group__httpcomponents5-family";
        writeHumanReviewReport(unitId, httpComponentsReport());
        RemediationSummary summary = summaryWithHumanReviewGroup(unitId);
        // The group's stable identity is its full unitId, not just the suffix after "group__" -- see
        // GitLabPublicationService#distinctHumanReviewGroups, which reads it two path segments up from
        // the human-review directory.
        String marker = "<!-- depbot-human-review:" + RUN_ID + ":" + unitId + " -->";
        gitLabClient.seedIssue(marker, IssueState.OPEN);
        gitLabClient.seedIssue(marker, IssueState.CLOSED);

        PublicationIndex index = service.publish(RUN_ID, new CohortsIndex(RUN_ID, List.of()), summary);

        assertEquals(IssuePublicationStatus.PUBLICATION_FAILED, index.humanReviewGroups().get(0).status());
        assertTrue(index.humanReviewGroups().get(0).errorMessage().contains("Found 2 issues"),
                index.humanReviewGroups().get(0).errorMessage());
        assertEquals(2, gitLabClient.issueCount());
    }

    // ---- remote identity: a run-wide gate, checked once, before any cohort is even looked at ----------

    @Test
    @DisplayName("a mismatched remote identity blocks the entire run before any cohort is looked at -- "
            + "every cohort and every Human Review group is reported failed, nothing is pushed or created")
    void mismatchedRemoteIdentityBlocksTheWholeRunBeforeAnyMutation() throws Exception {
        String branchName = "remediation/run1/hotfix-2026.1-3473b0daa6be";
        String commitSha = commitOnNewBranch(branchName, "pom.xml", "<project/>\n");
        Path reportPath = writeRemediationReport("high__group__g-mchange", mchangeReport(commitSha));
        String humanReviewUnitId = "high__group__httpcomponents5-family";
        writeHumanReviewReport(humanReviewUnitId, httpComponentsReport());

        RemoteIdentityVerifier alwaysMismatched = new RemoteIdentityVerifier() {
            @Override
            public VerificationResult verify(
                    GitCommandRunner git, Path repoPath, String remoteName, GitLabClient client, GitLabConfig config) {
                return VerificationResult.mismatch("git remote does not match the configured GitLab project");
            }
        };
        CountingPushGitCommandRunner countingGit = new CountingPushGitCommandRunner();
        GitLabConfig config = new GitLabConfig("https://gitlab.example.invalid", "123", "token-not-logged", "origin");
        GitLabPublicationService serviceUnderTest = new GitLabPublicationService(repo, countingGit, config,
                gitLabClient, runService, new RemediationReportMarkdownRenderer(),
                new HumanReviewReportMarkdownRenderer(), new PublicationSummaryMarkdownRenderer(),
                new PublicationIndexJsonRenderer(), alwaysMismatched);

        CohortsIndex cohortsIndex = new CohortsIndex(RUN_ID, List.of(new CohortsIndex.Entry(
                branchName, VERIFIED_REF, VERIFIED_SHA, RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-mchange", commitSha, reportPath.toString())))));
        RemediationSummary summary = summaryWithHumanReviewGroup(humanReviewUnitId);

        PublicationIndex index = serviceUnderTest.publish(RUN_ID, cohortsIndex, summary);

        assertEquals(0, countingGit.pushCount());
        assertEquals(0, gitLabClient.mergeRequestCount());
        assertEquals(0, gitLabClient.issueCount());
        assertEquals(RemediationCohort.PublicationStatus.PUBLICATION_FAILED, index.cohorts().get(0).status());
        assertEquals(IssuePublicationStatus.PUBLICATION_FAILED, index.humanReviewGroups().get(0).status());
        assertTrue(index.cohorts().get(0).errorMessage().contains("does not match"), index.cohorts().get(0).errorMessage());
    }
}
