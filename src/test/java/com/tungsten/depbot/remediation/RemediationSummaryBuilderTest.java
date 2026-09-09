package com.tungsten.depbot.remediation;

import com.tungsten.depbot.assessment.AnalysisRemediationGroup;
import com.tungsten.depbot.assessment.AssessmentConclusion;
import com.tungsten.depbot.assessment.Assessments;
import com.tungsten.depbot.assessment.AutomationSafety;
import com.tungsten.depbot.assessment.ImpactScorePolicy;
import com.tungsten.depbot.assessment.RemediationDecision;
import com.tungsten.depbot.assessment.RemediationVerdict;
import com.tungsten.depbot.claude.ClaudeRunOutcome;
import com.tungsten.depbot.git.ChangeDisposition;
import com.tungsten.depbot.git.ChangeOutcome;
import com.tungsten.depbot.git.RefsRefreshOutcome;
import com.tungsten.depbot.git.RestoreOutcome;
import com.tungsten.depbot.git.SourceRefVerification;
import com.tungsten.depbot.humanreview.HumanReviewOutcome;
import com.tungsten.depbot.humanreview.HumanReviewReport;
import com.tungsten.depbot.implementation.ImplementationOutcome;
import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;
import com.tungsten.depbot.jenkins.JenkinsValidationStatus;
import com.tungsten.depbot.validation.ValidationOutcome;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemediationSummaryBuilderTest {

    private static final ClaudeRunOutcome CLEAN_CALL =
            new ClaudeRunOutcome(true, 0, false, null, List.of("claude"), "start", "finish");
    private static final Path SOMEWHERE = Path.of("somewhere");

    private static RemediationSummary summaryOf(VulnerabilityRemediationOutcome... outcomes) {
        return RemediationSummaryBuilder.build("run1", "2026-08-10T10:00:00Z", "opus",
                "C:\\repo", null, List.of(outcomes));
    }

    /** Stopped before anything ran, because remote refs could not be refreshed. */
    private static VulnerabilityRemediationOutcome stoppedAtRefresh() {
        return new VulnerabilityRemediationOutcome("run1", "critical__g__a", "g:a",
                RefsRefreshOutcome.failed("could not reach origin"), null, null, null, null, null, null, null,
                null, null, null, null, null, RestoreOutcome.success(), RemediationStage.REMOTE_REFS_REFRESH,
                "could not reach origin");
    }

    /** A finding whose own conclusion decided everything -- no remediation group involved. */
    private static VulnerabilityRemediationOutcome withFindingDecision(
            AssessmentConclusion conclusion, RemediationDecision decision) {
        return new VulnerabilityRemediationOutcome("run1", "critical__g__a", "g:a",
                RefsRefreshOutcome.refreshed("origin"), conclusion, decision.verdict(), decision.reason(),
                null, null, null, null, null, null, null, null, null,
                RestoreOutcome.success(), RemediationStage.ASSESSMENT, decision.reason());
    }

    /** A REMEDIATION_REQUIRED finding whose group's own decision (score/automation-safety) applies. */
    private static VulnerabilityRemediationOutcome withGroupDecision(AnalysisRemediationGroup group) {
        RemediationDecision decision = ImpactScorePolicy.decide(group);
        return new VulnerabilityRemediationOutcome("run1", "critical__g__a", "g:a",
                RefsRefreshOutcome.refreshed("origin"), AssessmentConclusion.REMEDIATION_REQUIRED,
                decision.verdict(), decision.reason(), group.impactScore(), group.impactReason(),
                group.automationSafety(), group.automationSafetyReason(), null, null, null, null, null,
                RestoreOutcome.success(), RemediationStage.ASSESSMENT, decision.reason());
    }

    private static VulnerabilityRemediationOutcome committed() {
        return committedWithBuild(ValidationOutcome.passed("built fine", List.of("stub"), "stub output"));
    }

    /** A commit whose mandatory full build failed -- the commit stands, but is not fully validated. */
    private static VulnerabilityRemediationOutcome committedWithFailedBuild() {
        return committedWithBuild(
                ValidationOutcome.failed("tests failed", List.of("stub"), "stub output"));
    }

    private static VulnerabilityRemediationOutcome committedWithBuild(ValidationOutcome fullBuildValidation) {
        return committedWithBuild(Assessments.remediationGroup(2), fullBuildValidation);
    }

    private static VulnerabilityRemediationOutcome committedWithBuild(
            AnalysisRemediationGroup group, ValidationOutcome fullBuildValidation) {
        RemediationDecision decision = ImpactScorePolicy.decide(group);
        ImplementationOutcome implementation = new ImplementationOutcome("run1", "critical__g__a", "g:a",
                "remediation/run1/g-bcprov-0123456789ab", null,
                new ChangeOutcome(ChangeDisposition.COMMITTED_PENDING_VALIDATION, "abc123", "", List.of(),
                        "kept", null),
                null, fullBuildValidation, CLEAN_CALL, SOMEWHERE, null, Map.of());
        return new VulnerabilityRemediationOutcome("run1", "critical__g__a", "g:a",
                RefsRefreshOutcome.refreshed("origin"), AssessmentConclusion.REMEDIATION_REQUIRED,
                decision.verdict(), decision.reason(), group.impactScore(), group.impactReason(),
                group.automationSafety(), group.automationSafetyReason(),
                SourceRefVerification.verified("origin/release/9.2", "refs/remotes/origin/release/9.2",
                        "realsha", "claimedsha"),
                "remediation/run1/g-bcprov-0123456789ab", implementation, null, null, RestoreOutcome.success(),
                RemediationStage.IMPLEMENTATION, null);
    }

    /**
     * A group flagged {@code HUMAN_REVIEW_REQUIRED}: no implementation ever ran (the Remediation Engineer
     * never touches these groups), but a Human Review Report was prepared instead.
     */
    private static VulnerabilityRemediationOutcome humanReviewRequiredWithReport() {
        AnalysisRemediationGroup group = Assessments.withAutomationSafety(
                Assessments.remediationGroup(3), AutomationSafety.HUMAN_REVIEW_REQUIRED,
                "a coordinated dependency family with a proven binary-compatibility change");
        RemediationDecision decision = ImpactScorePolicy.decide(group);
        HumanReviewReport report = new HumanReviewReport("1.0", "g:a", "a coordinated version bump",
                "the transport library shares a binary-compatibility boundary with its client",
                "declared in the root pom", "raise both to the compatible pair", List.of(), "run the full suite",
                List.of(), List.of(), null, null);
        HumanReviewOutcome humanReview =
                new HumanReviewOutcome("run1", "critical__g__a", "g:a", report, CLEAN_CALL, SOMEWHERE, null);

        return new VulnerabilityRemediationOutcome("run1", "critical__g__a", "g:a",
                RefsRefreshOutcome.refreshed("origin"), AssessmentConclusion.REMEDIATION_REQUIRED,
                decision.verdict(), decision.reason(), group.impactScore(), group.impactReason(),
                group.automationSafety(), group.automationSafetyReason(), null, null, null, null, humanReview,
                RestoreOutcome.success(), RemediationStage.HUMAN_REVIEW, decision.reason());
    }

    @Test
    @DisplayName("committed, nothing-to-do and needs-a-human partition every library in a run")
    void theThreeCountsPartitionTheRun() {
        RemediationSummary summary = summaryOf(
                committed(),
                withFindingDecision(AssessmentConclusion.NO_ACTION_REQUIRED, ImpactScorePolicy.noActionRequired()),
                withGroupDecision(Assessments.withAutomationSafety(
                        Assessments.remediationGroup(9), AutomationSafety.AUTOMATION_BLOCKED,
                        "an architectural migration with no safe validation path")),
                withFindingDecision(AssessmentConclusion.INCONCLUSIVE, ImpactScorePolicy.inconclusive()),
                stoppedAtRefresh());

        assertEquals(5, summary.libraries().size());
        assertEquals(5, summary.committedCount() + summary.nothingToDoCount() + summary.needsAHumanCount(),
                "a library that falls into none of the three would be silently invisible");
        assertEquals(1, summary.committedCount());
        assertEquals(1, summary.nothingToDoCount());
        assertEquals(3, summary.needsAHumanCount());
    }

    @Test
    @DisplayName("fully-validated, build-failed, nothing-to-do and needs-a-human partition every library")
    void theFourCountsPartitionTheRun() {
        RemediationSummary summary = summaryOf(
                committed(),
                committedWithFailedBuild(),
                withFindingDecision(AssessmentConclusion.NO_ACTION_REQUIRED, ImpactScorePolicy.noActionRequired()),
                withGroupDecision(Assessments.withAutomationSafety(
                        Assessments.remediationGroup(9), AutomationSafety.AUTOMATION_BLOCKED,
                        "an architectural migration with no safe validation path")),
                stoppedAtRefresh());

        assertEquals(5, summary.libraries().size());
        assertEquals(5, summary.fullyValidatedCount() + summary.buildValidationFailedCount()
                        + summary.nothingToDoCount() + summary.needsAHumanCount(),
                "a library that falls into none of the four would be silently invisible");
        assertEquals(1, summary.fullyValidatedCount());
        assertEquals(1, summary.buildValidationFailedCount());
        assertEquals(1, summary.nothingToDoCount());
        assertEquals(2, summary.needsAHumanCount());
    }

    @Test
    @DisplayName("a commit whose mandatory build failed is not fully validated, but stays committed")
    void buildFailureIsNotFullyValidatedButStaysCommitted() {
        RemediationSummaryEntry entry = summaryOf(committedWithFailedBuild()).libraries().get(0);

        assertTrue(entry.committed(), "the commit itself is never undone by a failing build");
        assertFalse(entry.fullyValidated());
        assertTrue(entry.buildValidationFailed());
        assertFalse(entry.needsAHuman(),
                "buildValidationFailed is its own category, distinct from needsAHuman");
    }

    @Test
    @DisplayName("a library the run never reached counts as needing a human, not as a success")
    void aLibraryNeverReachedNeedsAHuman() {
        RemediationSummary summary = summaryOf(stoppedAtRefresh());

        RemediationSummaryEntry entry = summary.libraries().get(0);
        assertFalse(entry.committed());
        assertFalse(entry.nothingToDo());
        assertTrue(entry.needsAHuman(),
                "the fetch failed before the assessment ran; nothing about this library is known");
        assertNull(entry.verdict());
        assertEquals(RemediationStage.REMOTE_REFS_REFRESH, entry.reachedStage());
        assertEquals(1, summary.needsAHumanCount());
    }

    @Test
    @DisplayName("a committed library records the ref, git's commit, the branch and the commit sha")
    void aCommittedLibraryRecordsTheWholeChain() {
        RemediationSummaryEntry entry = summaryOf(committed()).libraries().get(0);

        assertEquals(RemediationVerdict.AUTOMATIC_ALLOWED, entry.verdict());
        assertEquals("refs/remotes/origin/release/9.2", entry.sourceRefResolved());
        assertEquals("realsha", entry.sourceCommitSha());
        assertEquals("claimedsha", entry.claimedSourceCommitSha());
        assertFalse(entry.claimedShaMatchedGit());
        assertEquals("remediation/run1/g-bcprov-0123456789ab", entry.branchName());
        assertEquals("abc123", entry.commitSha());
        assertTrue(entry.committed());
        assertTrue(entry.fullyValidated());
        assertFalse(entry.buildValidationFailed());
        assertTrue(entry.fullBuildLogPath().endsWith("full-build-output.txt"), entry.fullBuildLogPath());
        assertEquals(AutomationSafety.AUTOMATIC_ALLOWED, entry.automationSafety());
        assertEquals("no coordinated or runtime-sensitive dependency is involved",
                entry.automationSafetyReason());
    }

    @Test
    @DisplayName("a group flagged for human review is its own category: never committed, but a report "
            + "exists, distinct from needsAHuman and visible in the summary")
    void humanReviewRequiredIsItsOwnCategory() {
        RemediationSummary summary = summaryOf(committed(), humanReviewRequiredWithReport());
        RemediationSummaryEntry entry = summary.libraries().get(1);

        assertEquals(RemediationVerdict.HUMAN_REVIEW_REQUIRED, entry.verdict());
        assertEquals(AutomationSafety.HUMAN_REVIEW_REQUIRED, entry.automationSafety());
        assertEquals("a coordinated dependency family with a proven binary-compatibility change",
                entry.automationSafetyReason());
        assertFalse(entry.committed(),
                "the Remediation Engineer never runs for a HUMAN_REVIEW_REQUIRED group -- nothing is ever "
                        + "implemented or committed for it");
        assertFalse(entry.needsAHuman(),
                "humanReviewRequired is its own category, distinct from needsAHuman, independent of committed()");
        assertTrue(entry.humanReviewRequired());
        assertTrue(entry.humanReviewReportProduced());
        assertEquals("a coordinated version bump", entry.humanReviewVulnerabilitySummary());
        assertEquals(1, summary.humanReviewRequiredCount());
    }

    private static JenkinsValidationOutcome jenkinsSuccess(String candidateSha) {
        return new JenkinsValidationOutcome(JenkinsValidationStatus.SUCCESS, "WebApplicationDependencyValidation",
                1, "http://jenkins.example/job/x/1/", "baselinesha", candidateSha, "treesha", 42L,
                "Jenkins reported result SUCCESS");
    }

    private static JenkinsValidationOutcome jenkinsFailure(String candidateSha) {
        return new JenkinsValidationOutcome(JenkinsValidationStatus.FAILED, "WebApplicationDependencyValidation",
                2, "http://jenkins.example/job/x/2/", "baselinesha", candidateSha, "treesha", 12L,
                "Jenkins reported result FAILURE");
    }

    /**
     * One member of a committed group, carrying the group's own strict {@link RemediationReport}. Puts
     * the group on its own branch, named after {@code groupId} -- correct for a test where every group is
     * its own cohort; a test that needs several groups to share ONE real cohort must use the overload
     * below and pass the SAME {@code branchName} for each of them, exactly as {@code
     * VulnerabilityRemediationService} always does for every member of one cohort.
     */
    private static VulnerabilityRemediationOutcome committedGroupMember(
            String coordinates, String groupId, String commitSha,
            JenkinsValidationOutcome isolated, JenkinsValidationOutcome integration) {
        return committedGroupMember(
                coordinates, groupId, "remediation/run1/" + groupId, commitSha, isolated, integration);
    }

    /**
     * As the four-argument overload, but with an explicit {@code branchName} -- the cohort's own real
     * identity (see {@code RemediationSummary#integrationOutcomesByCohort}). Several groups sharing one
     * cohort must be built with the same {@code branchName}, never inferred from {@code groupId}.
     */
    private static VulnerabilityRemediationOutcome committedGroupMember(
            String coordinates, String groupId, String branchName, String commitSha,
            JenkinsValidationOutcome isolated, JenkinsValidationOutcome integration) {
        AnalysisRemediationGroup group = Assessments.remediationGroup(groupId, 2);
        RemediationDecision decision = ImpactScorePolicy.decide(group);
        ImplementationOutcome implementation = new ImplementationOutcome(
                "run1", "high__group__" + groupId, coordinates, branchName, null,
                new ChangeOutcome(ChangeDisposition.COMMITTED_PENDING_VALIDATION, commitSha, "", List.of(),
                        "kept", null),
                null, ValidationOutcome.passed("built fine", List.of("stub"), "stub output"),
                CLEAN_CALL, SOMEWHERE, null, Map.of());
        RemediationReport report = new RemediationReport(
                RemediationReport.CURRENT_SCHEMA_VERSION, commitSha, groupId, List.of(coordinates),
                "changed", "necessary", "why", List.of("pom.xml"), "validated", List.of(),
                com.tungsten.depbot.validation.ValidationStatus.PASSED,
                com.tungsten.depbot.validation.ValidationStatus.PASSED, isolated, integration);
        return new VulnerabilityRemediationOutcome("run1", "high__group__" + groupId, coordinates,
                RefsRefreshOutcome.refreshed("origin"), AssessmentConclusion.REMEDIATION_REQUIRED,
                decision.verdict(), decision.reason(), group.impactScore(), group.impactReason(),
                group.automationSafety(), group.automationSafetyReason(),
                SourceRefVerification.verified("origin/release/9.2", "refs/remotes/origin/release/9.2",
                        "realsha", "claimedsha"),
                branchName, implementation, report, null, RestoreOutcome.success(),
                RemediationStage.IMPLEMENTATION, null);
    }

    @Test
    @DisplayName("libraries, remediation groups and commits are three distinct counts -- a multi-library "
            + "group never inflates the group/commit count the way it correctly does inflate the library count")
    void librariesGroupsAndCommitsAreDistinctCounts() {
        JenkinsValidationOutcome mchangeIsolated = jenkinsSuccess("mchange-candidate-sha");
        JenkinsValidationOutcome mchangeIntegration = jenkinsSuccess("mchange-integration-sha");
        JenkinsValidationOutcome bcprovIsolated = jenkinsSuccess("bcprov-candidate-sha");
        JenkinsValidationOutcome bcprovIntegration = jenkinsSuccess("bcprov-integration-sha");

        RemediationSummary summary = summaryOf(
                committedGroupMember("com.mchange:c3p0", "grp-mchange", "shared-mchange-sha",
                        mchangeIsolated, mchangeIntegration),
                committedGroupMember("com.mchange:mchange-commons-java", "grp-mchange", "shared-mchange-sha",
                        mchangeIsolated, mchangeIntegration),
                committedGroupMember("org.bouncycastle:bcprov-jdk18on", "grp-bcprov", "bcprov-sha",
                        bcprovIsolated, bcprovIntegration));

        assertEquals(3, summary.librariesRemediatedCount(), "three libraries were actually remediated");
        assertEquals(2, summary.automaticGroupCount(),
                "two libraries of grp-mchange share exactly one group, never counted as two");
        assertEquals(2, summary.commitCount(), "one commit per group -- never one per library");
        assertEquals(2, summary.isolatedJenkinsValidatedGroupCount());
        assertEquals(2, summary.integrationJenkinsAttemptedCohortCount());
        assertEquals(2, summary.integrationJenkinsSucceededCohortCount());
        assertEquals(2, summary.readyToPublishGroupCount());
    }

    @Test
    @DisplayName("integration cohort counts are distinct cohorts, not distinct groups/reports sharing one "
            + "result -- four groups of ONE cohort, one shared integration Jenkins SUCCESS, must count as "
            + "exactly one cohort attempted and one succeeded, never four")
    void integrationCohortCountsCountDistinctCohortsNotGroupsSharingOneResult() {
        JenkinsValidationOutcome sharedIntegration = jenkinsSuccess("assembled-tip-sha");
        String sharedCohortBranch = "remediation/run1/refs_remotes_origin_hotfix-2026.1-3473b0daa6be";

        RemediationSummary summary = summaryOf(
                committedGroupMember("org.bouncycastle:bcprov-jdk18on", "grp-bcprov", sharedCohortBranch,
                        "bcprov-sha", jenkinsSuccess("bcprov-candidate-sha"), sharedIntegration),
                committedGroupMember("com.mchange:c3p0", "grp-mchange", sharedCohortBranch,
                        "mchange-sha", jenkinsSuccess("mchange-candidate-sha"), sharedIntegration),
                committedGroupMember("com.fasterxml.jackson.core:jackson-databind", "grp-jackson", sharedCohortBranch,
                        "jackson-sha", jenkinsSuccess("jackson-candidate-sha"), sharedIntegration),
                committedGroupMember("org.apache.logging.log4j:log4j-api", "grp-log4j", sharedCohortBranch,
                        "log4j-sha", jenkinsSuccess("log4j-candidate-sha"), sharedIntegration));

        assertEquals(4, summary.automaticGroupCount());
        assertEquals(4, summary.commitCount());
        assertEquals(4, summary.isolatedJenkinsValidatedGroupCount());
        assertEquals(1, summary.integrationJenkinsAttemptedCohortCount(),
                "all four groups share ONE cohort branch and ONE integration Jenkins execution -- this "
                        + "must count as one cohort, not four (one per Remediation Report that happens to "
                        + "repeat it)");
        assertEquals(1, summary.integrationJenkinsSucceededCohortCount());
        assertEquals(4, summary.readyToPublishGroupCount());
    }

    @Test
    @DisplayName("two genuinely different cohorts are never collapsed into one just because their "
            + "integration Jenkins outcomes happen to be field-for-field equal -- cohort identity comes "
            + "from branchName, never from JenkinsValidationOutcome value-equality")
    void twoDifferentCohortsWithCoincidentallyIdenticalIntegrationOutcomesAreNeverCollapsed() {
        // Deliberately the SAME JenkinsValidationOutcome value for two DIFFERENT cohort branches --
        // exactly the case that would fool a value-equality-based identity into reporting one cohort.
        JenkinsValidationOutcome coincidentallyIdenticalIntegration = jenkinsSuccess("same-looking-tip-sha");

        RemediationSummary summary = summaryOf(
                committedGroupMember("org.bouncycastle:bcprov-jdk18on", "grp-bcprov",
                        "remediation/run1/refs_remotes_origin_hotfix-2026.1-aaaaaaaaaaaa", "bcprov-sha",
                        jenkinsSuccess("bcprov-candidate-sha"), coincidentallyIdenticalIntegration),
                committedGroupMember("com.mchange:c3p0", "grp-mchange",
                        "remediation/run1/refs_remotes_origin_release-9.2-bbbbbbbbbbbb", "mchange-sha",
                        jenkinsSuccess("mchange-candidate-sha"), coincidentallyIdenticalIntegration));

        assertEquals(2, summary.integrationJenkinsAttemptedCohortCount(),
                "two different cohort branches must count as two cohorts, even though their "
                        + "JenkinsValidationOutcome values are equal");
        assertEquals(2, summary.integrationJenkinsSucceededCohortCount());
    }

    @Test
    @DisplayName("a group whose final integration gate failed is never ready to publish, even though its "
            + "own isolated Jenkins validation succeeded")
    void failedIntegrationGateIsNeverReadyToPublishDespiteSuccessfulIsolation() {
        JenkinsValidationOutcome isolated = jenkinsSuccess("candidate-sha");
        JenkinsValidationOutcome failedIntegration = jenkinsFailure("integration-sha");

        RemediationSummary summary = summaryOf(
                committedGroupMember("org.bouncycastle:bcprov-jdk18on", "grp-bcprov", "bcprov-sha",
                        isolated, failedIntegration));
        RemediationSummaryEntry entry = summary.libraries().get(0);

        assertTrue(entry.isolatedJenkinsValidated());
        assertFalse(entry.integrationJenkinsValidated());
        assertFalse(entry.readyToPublish(),
                "a successful isolated validation alone must never be reported as ready to publish");
        assertEquals(1, summary.isolatedJenkinsValidatedGroupCount());
        assertEquals(1, summary.integrationJenkinsAttemptedCohortCount());
        assertEquals(0, summary.integrationJenkinsSucceededCohortCount());
        assertEquals(0, summary.readyToPublishGroupCount());
    }

    @Test
    @DisplayName("Human Review groups and libraries are counted separately -- a shared review directory "
            + "counts once as a group, but once per library")
    void humanReviewGroupsAndLibrariesAreDistinctCounts() {
        HumanReviewReport report = new HumanReviewReport("1.0", "com.mchange:c3p0, com.mchange:mchange-commons-java",
                "a coordinated version bump", "shares a binary-compatibility boundary", "declared in the root pom",
                "raise both to the compatible pair", List.of(), "run the full suite", List.of(), List.of(),
                null, null);
        HumanReviewOutcome sharedReview = new HumanReviewOutcome(
                "run1", "high__group__grp-mchange", "com.mchange:c3p0, com.mchange:mchange-commons-java",
                report, CLEAN_CALL, Path.of("shared-review-dir"), null);

        VulnerabilityRemediationOutcome member1 = new VulnerabilityRemediationOutcome("run1",
                "high__group__grp-mchange", "com.mchange:c3p0", RefsRefreshOutcome.refreshed("origin"),
                AssessmentConclusion.REMEDIATION_REQUIRED, RemediationVerdict.HUMAN_REVIEW_REQUIRED, "reason",
                null, null, AutomationSafety.HUMAN_REVIEW_REQUIRED, "reason", null, null, null, null,
                sharedReview, RestoreOutcome.success(), RemediationStage.HUMAN_REVIEW, "reason");
        VulnerabilityRemediationOutcome member2 = new VulnerabilityRemediationOutcome("run1",
                "high__group__grp-mchange", "com.mchange:mchange-commons-java", RefsRefreshOutcome.refreshed("origin"),
                AssessmentConclusion.REMEDIATION_REQUIRED, RemediationVerdict.HUMAN_REVIEW_REQUIRED, "reason",
                null, null, AutomationSafety.HUMAN_REVIEW_REQUIRED, "reason", null, null, null, null,
                sharedReview, RestoreOutcome.success(), RemediationStage.HUMAN_REVIEW, "reason");

        RemediationSummary summary = summaryOf(member1, member2, committed());

        assertEquals(1, summary.humanReviewGroupCount(),
                "both members share one humanReviewDirectory, so this is one group, not two");
        assertEquals(2, summary.humanReviewLibraryCount());
    }

    @Test
    @DisplayName("stages never reached are absent rather than guessed at")
    void unreachedStagesAreAbsent() {
        RemediationSummaryEntry entry =
                summaryOf(withGroupDecision(Assessments.withAutomationSafety(
                        Assessments.remediationGroup(9), AutomationSafety.AUTOMATION_BLOCKED,
                        "an architectural migration with no safe validation path"))).libraries().get(0);

        assertEquals(RemediationVerdict.MANUAL_REMEDIATION_REQUIRED, entry.verdict());
        assertEquals(9, entry.impactScore());
        assertNull(entry.sourceRefResolved(), "verification never ran, so it has nothing to report");
        assertNull(entry.branchName());
        assertNull(entry.changeDisposition());
        assertNull(entry.validationStatus());
    }

    /** A group that was attempted, rolled back, and still produced a Human Review report -- the shape
     *  every rejected {@code AUTOMATIC_ALLOWED} group takes regardless of which {@link RejectionStage}
     *  the rejection actually happened at. */
    private static VulnerabilityRemediationOutcome rejectedWithReport(ValidationOutcome fullBuildValidation) {
        AnalysisRemediationGroup group = Assessments.remediationGroup(4);
        RemediationDecision decision = ImpactScorePolicy.decide(group);
        ImplementationOutcome implementation = new ImplementationOutcome("run1", "critical__g__a", "g:a",
                "remediation/run1/g-bcprov-0123456789ab", null,
                new ChangeOutcome(ChangeDisposition.ROLLED_BACK, null, "", List.of(), "rolled back", null),
                null, fullBuildValidation, CLEAN_CALL, SOMEWHERE, null, Map.of());
        HumanReviewReport report = new HumanReviewReport("1.0", "g:a", "a vulnerability",
                "an outdated version is pinned", "declared directly", "raise the version", List.of(),
                "run the test suite", List.of(), List.of(), null, null);
        HumanReviewOutcome humanReview =
                new HumanReviewOutcome("run1", "critical__g__a", "g:a", report, CLEAN_CALL, SOMEWHERE, null);
        return new VulnerabilityRemediationOutcome("run1", "critical__g__a", "g:a",
                RefsRefreshOutcome.refreshed("origin"), AssessmentConclusion.REMEDIATION_REQUIRED,
                decision.verdict(), decision.reason(), group.impactScore(), group.impactReason(),
                group.automationSafety(), group.automationSafetyReason(),
                SourceRefVerification.verified("origin/release/9.2", "refs/remotes/origin/release/9.2",
                        "realsha", "claimedsha"),
                "remediation/run1/g-bcprov-0123456789ab", implementation, null, humanReview,
                RestoreOutcome.success(), RemediationStage.IMPLEMENTATION, decision.reason());
    }

    @Test
    @DisplayName("groupOutcomeState is computed independently of RejectionStage -- two rejections at "
            + "different stages both classify as AUTOMATIC_REJECTED_WITH_REPORT")
    void outcomeStateAndRejectionStageAreIndependent() {
        // classifyOutcomeState(VulnerabilityRemediationOutcome) has no RejectionStage/RejectedGroupOutcome
        // parameter at all -- it can only ever read committed()/humanReviewOutcome()/restore()/reachedStage()/
        // verdict(). This constructs two realistic rejections that a real run would record with two DIFFERENT
        // RejectionStage values (a full-build failure vs. a dependency-validation-style failure) and confirms
        // both collapse to the exact same GroupOutcomeState, proving the state is never derived from, or
        // conflated with, whichever specific stage actually caused the rejection.
        VulnerabilityRemediationOutcome fullBuildFailure =
                rejectedWithReport(ValidationOutcome.failed("full build failed", List.of("stub"), "stub output"));
        VulnerabilityRemediationOutcome dependencyValidationStyleFailure =
                rejectedWithReport(null);   // never reached the full build at all -- an earlier-stage rejection

        RemediationSummary summary = summaryOf(fullBuildFailure, dependencyValidationStyleFailure);

        assertEquals(GroupOutcomeState.AUTOMATIC_REJECTED_WITH_REPORT,
                summary.libraries().get(0).groupOutcomeState());
        assertEquals(GroupOutcomeState.AUTOMATIC_REJECTED_WITH_REPORT,
                summary.libraries().get(1).groupOutcomeState());
    }

    // ---- failureCount must not double-count a handled automatic-rejection-with-report as a failure -----
    //
    // Production defect (pilot 20260908-220923-771c06): a Jackson group whose automatic attempt was
    // rejected but which still produced a working Human Review report was counted both under "automatic
    // attempt rejected but a Human Review report was produced (handled, not an unexplained failure)" AND
    // under "Failures" -- contradicting the console's own printed definition of that line ("build
    // validation failed, or needs a human with no report at all").

    @Test
    @DisplayName("an automatic attempt rejected but with a Human Review report produced is not a failure -- "
            + "needsAHuman still counts it (the run must still resolve to MANUAL_REMEDIATION_REQUIRED), but "
            + "failureCount must not")
    void automaticRejectedWithReportIsNeedsAHumanButNotAFailure() {
        RemediationSummary summary = summaryOf(rejectedWithReport(
                ValidationOutcome.passed("built fine", List.of("stub"), "stub output")));

        assertEquals(GroupOutcomeState.AUTOMATIC_REJECTED_WITH_REPORT,
                summary.libraries().get(0).groupOutcomeState());
        assertEquals(1, summary.needsAHumanCount());
        assertEquals(1, summary.automaticRejectedWithReportCount());
        assertEquals(0, summary.automaticRejectedNoReportCount());
        assertEquals(0, summary.failureCount(),
                "a handled automatic-rejection-with-report must not also be counted as a failure");
    }

    @Test
    @DisplayName("an automatic attempt rejected with no Human Review report at all is still a genuine "
            + "failure -- the failureCount fix must not over-correct")
    void automaticRejectedWithNoReportIsStillAFailure() {
        AnalysisRemediationGroup group = Assessments.remediationGroup(4);
        RemediationDecision decision = ImpactScorePolicy.decide(group);
        ImplementationOutcome implementation = new ImplementationOutcome("run1", "critical__g__a", "g:a",
                "remediation/run1/g-bcprov-0123456789ab", null,
                new ChangeOutcome(ChangeDisposition.ROLLED_BACK, null, "", List.of(), "rolled back", null),
                null, null, CLEAN_CALL, SOMEWHERE, null, Map.of());
        VulnerabilityRemediationOutcome noReport = new VulnerabilityRemediationOutcome("run1", "critical__g__a",
                "g:a", RefsRefreshOutcome.refreshed("origin"), AssessmentConclusion.REMEDIATION_REQUIRED,
                decision.verdict(), decision.reason(), group.impactScore(), group.impactReason(),
                group.automationSafety(), group.automationSafetyReason(),
                SourceRefVerification.verified("origin/release/9.2", "refs/remotes/origin/release/9.2",
                        "realsha", "claimedsha"),
                "remediation/run1/g-bcprov-0123456789ab", implementation, null, null,
                RestoreOutcome.success(), RemediationStage.IMPLEMENTATION, decision.reason());

        RemediationSummary summary = summaryOf(noReport);

        assertEquals(GroupOutcomeState.AUTOMATIC_REJECTED_NO_REPORT,
                summary.libraries().get(0).groupOutcomeState());
        assertEquals(1, summary.needsAHumanCount());
        assertEquals(0, summary.automaticRejectedWithReportCount());
        assertEquals(1, summary.automaticRejectedNoReportCount());
        assertEquals(1, summary.failureCount(),
                "a genuinely unhandled rejection (no report at all) must still count as a failure");
    }
}
