package com.tungsten.depbot.remediation;

import com.tungsten.depbot.assessment.AssessmentConclusion;
import com.tungsten.depbot.assessment.AutomationSafety;
import com.tungsten.depbot.assessment.RemediationVerdict;
import com.tungsten.depbot.git.ChangeDisposition;
import com.tungsten.depbot.implementation.ImplementationConclusion;
import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;
import com.tungsten.depbot.validation.ValidationStatus;
import com.fasterxml.jackson.annotation.JsonIgnore;


/**
 * One library's line in the run summary: what was decided at each gate, and where to read the detail.
 *
 * <p>This exists so that after a run there is a single small file answering "what happened, and where do I
 * look" -- the assessment, the ref that was chosen and the commit git resolved for it, the branch, the
 * implementation's own report, the diff, the validation verdict, and the commit if there was one. Every
 * field is derived from artifacts that already exist; nothing is recorded only here.
 *
 * <p>A {@code null} field means that gate was never reached, which is itself the answer.
 */
public record RemediationSummaryEntry(
        String coordinates,
        String unitId,
        RemediationStage reachedStage,

        AssessmentConclusion assessmentConclusion,
        Integer impactScore,
        RemediationVerdict verdict,
        AutomationSafety automationSafety,
        String automationSafetyReason,

        String sourceRefRequested,
        String sourceRefResolved,
        String sourceCommitSha,
        String claimedSourceCommitSha,
        Boolean claimedShaMatchedGit,

        String branchName,
        ImplementationConclusion implementationConclusion,
        ValidationStatus validationStatus,
        String validationReason,
        ValidationStatus fullBuildValidationStatus,
        String fullBuildValidationReason,
        String fullBuildLogPath,
        ChangeDisposition changeDisposition,
        String commitSha,

        String groupId,
        JenkinsValidationOutcome isolatedJenkinsValidation,
        JenkinsValidationOutcome integrationJenkinsValidation,

        String stopReason,
        String assessmentDirectory,
        String implementationDirectory,

        String humanReviewDirectory,
        Boolean humanReviewReportProduced,
        String humanReviewVulnerabilitySummary,
        String humanReviewWhyVulnerable,
        String humanReviewDependencyOrigin,
        String humanReviewRecommendedChange,
        java.util.List<String> humanReviewRelatedDependencies,
        String humanReviewValidationApproach,
        java.util.List<String> humanReviewOpenQuestions,

        GroupOutcomeState groupOutcomeState) {

    /**
     * Backward-compatible shape from before {@code groupOutcomeState} existed -- defaults it to
     * {@code null}. Kept so any fixture/test predating this field keeps compiling unchanged.
     */
    public RemediationSummaryEntry(
            String coordinates, String unitId, RemediationStage reachedStage,
            AssessmentConclusion assessmentConclusion, Integer impactScore, RemediationVerdict verdict,
            AutomationSafety automationSafety, String automationSafetyReason,
            String sourceRefRequested, String sourceRefResolved, String sourceCommitSha,
            String claimedSourceCommitSha, Boolean claimedShaMatchedGit,
            String branchName, ImplementationConclusion implementationConclusion,
            ValidationStatus validationStatus, String validationReason,
            ValidationStatus fullBuildValidationStatus, String fullBuildValidationReason,
            String fullBuildLogPath, ChangeDisposition changeDisposition, String commitSha,
            String groupId, JenkinsValidationOutcome isolatedJenkinsValidation,
            JenkinsValidationOutcome integrationJenkinsValidation,
            String stopReason, String assessmentDirectory, String implementationDirectory,
            String humanReviewDirectory, Boolean humanReviewReportProduced,
            String humanReviewVulnerabilitySummary, String humanReviewWhyVulnerable,
            String humanReviewDependencyOrigin, String humanReviewRecommendedChange,
            java.util.List<String> humanReviewRelatedDependencies, String humanReviewValidationApproach,
            java.util.List<String> humanReviewOpenQuestions) {
        this(coordinates, unitId, reachedStage, assessmentConclusion, impactScore, verdict, automationSafety,
                automationSafetyReason, sourceRefRequested, sourceRefResolved, sourceCommitSha,
                claimedSourceCommitSha, claimedShaMatchedGit, branchName, implementationConclusion,
                validationStatus, validationReason, fullBuildValidationStatus, fullBuildValidationReason,
                fullBuildLogPath, changeDisposition, commitSha, groupId, isolatedJenkinsValidation,
                integrationJenkinsValidation, stopReason, assessmentDirectory, implementationDirectory,
                humanReviewDirectory, humanReviewReportProduced, humanReviewVulnerabilitySummary,
                humanReviewWhyVulnerable, humanReviewDependencyOrigin, humanReviewRecommendedChange,
                humanReviewRelatedDependencies, humanReviewValidationApproach, humanReviewOpenQuestions, null);
    }

    /** Whether this library ended with a change kept on its remediation branch -- a technical fact only. */
    public boolean committed() {
        return changeDisposition == ChangeDisposition.COMMITTED_PENDING_VALIDATION;
    }

    /** Whether the run's honest answer was that there is nothing to do here. */
    public boolean nothingToDo() {
        return verdict == RemediationVerdict.NO_ACTION_REQUIRED;
    }

    /**
     * Committed, and the pilot's mandatory full local build then confirmed it. The only state that counts
     * as a finished remediation -- {@link #committed()} alone no longer does, now that a full
     * {@code mvn -B package} runs on every commit before it is trusted.
     */
    public boolean fullyValidated() {
        return committed() && fullBuildValidationStatus == ValidationStatus.PASSED;
    }

    /**
     * Committed, but the mandatory full build did not pass. The commit is kept for diagnosis -- a failed
     * build is never grounds to undo it -- so this is a distinct outcome from {@link #needsAHuman()}: the
     * library did get a change, it just was not confirmed to build.
     */
    public boolean buildValidationFailed() {
        return committed() && fullBuildValidationStatus != null
                && fullBuildValidationStatus != ValidationStatus.PASSED;
    }

    /** Whether isolated Jenkins validation ran for this library's group and reported success. */
    @JsonIgnore
    public boolean isolatedJenkinsValidated() {
        return isolatedJenkinsValidation != null && isolatedJenkinsValidation.succeeded();
    }

    /**
     * Whether the final, whole-cohort integration Jenkins gate ran and reported success. The same
     * {@link JenkinsValidationOutcome} instance is shared by every library in the same cohort, so this
     * is never, by itself, evidence that reading it from a different library would differ.
     */
    public boolean integrationJenkinsValidated() {
        return integrationJenkinsValidation != null && integrationJenkinsValidation.succeeded();
    }

    /**
     * The one predicate that means "actually ready to publish": committed, and both the isolated and the
     * final integration Jenkins gates succeeded. Deliberately requires both -- a successful isolated
     * validation is never, by itself, proof that the assembled branch is also valid; see
     * {@link RemediationReport#jenkinsValidated()}, which this mirrors.
     */
    public boolean readyToPublish() {
        return committed() && isolatedJenkinsValidated() && integrationJenkinsValidated();
    }

    /**
     * A group Vulnerability Analysis itself flagged unsafe to trust to automation ({@code
     * HUMAN_REVIEW_REQUIRED}, or legacy {@code AUTOMATION_BLOCKED} treated identically) that never ended
     * up committed, and for which a Human Review Report was actually produced. All three conditions
     * matter: {@code automationSafety} alone is not enough, since such a group may still be genuinely
     * attempted through its own isolated, risky singleton cohort and either succeed (a commit, no report
     * -- excluded by {@link #committed()}) or fail without ever producing a report (excluded by the
     * report check); and an {@code AUTOMATIC_ALLOWED} group that was attempted and rejected with a
     * report is a different, already-distinct shape ({@code GroupOutcomeState#AUTOMATIC_REJECTED_WITH_REPORT}),
     * not this one -- {@code automationSafety} is what tells them apart.
     */
    public boolean humanReviewRequired() {
        return (automationSafety == AutomationSafety.HUMAN_REVIEW_REQUIRED
                        || automationSafety == AutomationSafety.AUTOMATION_BLOCKED)
                && !committed()
                && Boolean.TRUE.equals(humanReviewReportProduced);
    }

    /**
     * Whether this library is left for a person for a reason upstream of the build -- the assessment, the
     * ref, or the implementation itself never produced a kept commit at all, and it is not already
     * accounted for by {@link #humanReviewRequired()}'s own, more specific Human Review Report.
     *
     * <p>Defined by exclusion, and that is deliberate: anything that is neither a kept change, an
     * evidenced "nothing to do", nor a prepared Human Review Report needs someone to look at it with no
     * lead at all. Enumerating the reasons instead would mean every new way of stopping had to be
     * remembered here, and the one that was forgotten -- a library the run never even reached because the
     * fetch failed -- would be counted as a success. Kept distinct from {@link #buildValidationFailed()}
     * so an operator can tell "never got a change" from "got a change that then failed to build" at a
     * glance; a run's overall need for a human counts both.
     *
     * <p>{@link GroupOutcomeState#ANALYSIS_INCOMPLETE} is the one further exclusion: a library that never
     * even got a per-finding verdict because its whole batch's Vulnerability Analysis was ruled incomplete
     * is not this library's own independent failure to be counted alongside every other one that shares
     * the same incomplete batch -- see {@link RemediationSummary#analysisIncompleteFindingCount()}, which
     * counts that population under its own, honestly-batch-scoped name instead.
     */
    public boolean needsAHuman() {
        return !committed() && !nothingToDo() && !humanReviewRequired()
                && groupOutcomeState != GroupOutcomeState.ANALYSIS_INCOMPLETE;
    }
}
