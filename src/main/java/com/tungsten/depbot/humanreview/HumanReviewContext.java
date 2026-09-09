package com.tungsten.depbot.humanreview;

import com.tungsten.depbot.assessment.AnalysisRemediationGroup;
import com.tungsten.depbot.assessment.FindingAssessment;
import com.tungsten.depbot.assessment.VulnerabilityWorkItem;
import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/**
 * Everything the Human Review Engineer needs -- covers all three shapes this call can be asked to
 * write a report for:
 *
 * <ul>
 *   <li>A validated {@link AnalysisRemediationGroup} the analysis flagged {@code HUMAN_REVIEW_REQUIRED}
 *       or {@code AUTOMATION_BLOCKED} -- {@code group} and {@code findingAssessments} are both present.
 *   <li>A single finding whose conclusion was {@code INCONCLUSIVE} -- no group, one entry in
 *       {@code workItems} and {@code findingAssessments}.
 *   <li>A single finding from a batch whose analysis failed outright -- no group, no
 *       {@code FindingAssessment} at all (the list is empty), and {@code priorAnalysisFailureContext}
 *       carries whatever could be salvaged from the failed attempt.
 * </ul>
 *
 * <p>{@code reviewedRef}/{@code reviewedSha} are null when no ref could be verified or none was named --
 * the review still runs, against the current checkout, rather than being blocked on a ref.
 *
 * <p>{@code cumulativeJenkinsValidation}/{@code integrationJenkinsValidation} are bot-owned structured
 * facts, never Claude-summarized: at most one is ever set on a given context, depending on which of
 * {@code VulnerabilityRemediationService}'s Jenkins-related Human Review paths constructed it -- a
 * rejected group's own cumulative Jenkins outcome, or a cohort-level failed final integration review.
 * Both {@code null} means Jenkins was never reached for this review at all (a group with no candidate, an
 * {@code INCONCLUSIVE} finding, a failed batch analysis, or a local-validation failure before any commit).
 * This context is never persisted/read back -- unlike {@code RemediationReport}/{@code HumanReviewReport}
 * it carries no backward-compatibility burden, so its Jenkins field is named for what it actually is now.
 *
 * <p>{@code rejectedGroupOutcome} is the bot-assembled dossier of exactly why an <em>attempted</em>
 * automatic group was rejected (see {@code RejectedGroupOutcome}) -- {@code null} for every other shape
 * this context covers (a group never attempted at all, an ungrouped finding, a cohort-level review).
 *
 * <p>{@code cohortIntegrationFailure} is the bot-assembled dossier for the OTHER cohort-level review
 * shape: every group in the cohort was individually accepted, but the fully assembled branch failed its
 * own separate final-integration Jenkins gate (see {@code CohortIntegrationFailureOutcome}). Mutually
 * exclusive with {@code rejectedGroupOutcome} in practice -- one is about a single rejected group, the
 * other about the whole assembled set; a given review is never about both at once.
 */
public record HumanReviewContext(
        String runId,
        String unitId,
        Path workspace,
        String reviewedRef,
        String reviewedSha,
        List<VulnerabilityWorkItem> workItems,
        List<FindingAssessment> findingAssessments,
        AnalysisRemediationGroup group,
        String decisionReason,
        List<String> companionCoordinates,
        String priorAnalysisFailureContext,
        JenkinsValidationOutcome cumulativeJenkinsValidation,
        JenkinsValidationOutcome integrationJenkinsValidation,
        com.tungsten.depbot.remediation.RejectedGroupOutcome rejectedGroupOutcome,
        com.tungsten.depbot.remediation.CohortIntegrationFailureOutcome cohortIntegrationFailure) {

    public HumanReviewContext {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(unitId, "unitId");
        Objects.requireNonNull(workspace, "workspace");
        Objects.requireNonNull(decisionReason, "decisionReason");
        if (workItems == null || workItems.isEmpty()) {
            throw new IllegalArgumentException("a human review context must cover at least one finding");
        }
        workItems = List.copyOf(workItems);
        findingAssessments = findingAssessments == null ? List.of() : List.copyOf(findingAssessments);
        companionCoordinates = companionCoordinates == null ? List.of() : List.copyOf(companionCoordinates);
    }

    /**
     * Backward-compatible shape from before {@code cohortIntegrationFailure} existed -- defaults it to
     * {@code null}. Kept so every existing caller that never needed it keeps compiling unchanged.
     */
    public HumanReviewContext(
            String runId,
            String unitId,
            Path workspace,
            String reviewedRef,
            String reviewedSha,
            List<VulnerabilityWorkItem> workItems,
            List<FindingAssessment> findingAssessments,
            AnalysisRemediationGroup group,
            String decisionReason,
            List<String> companionCoordinates,
            String priorAnalysisFailureContext,
            JenkinsValidationOutcome cumulativeJenkinsValidation,
            JenkinsValidationOutcome integrationJenkinsValidation,
            com.tungsten.depbot.remediation.RejectedGroupOutcome rejectedGroupOutcome) {
        this(runId, unitId, workspace, reviewedRef, reviewedSha, workItems, findingAssessments, group,
                decisionReason, companionCoordinates, priorAnalysisFailureContext, cumulativeJenkinsValidation,
                integrationJenkinsValidation, rejectedGroupOutcome, null);
    }

    /**
     * Backward-compatible shape from before {@code rejectedGroupOutcome} existed -- defaults it to
     * {@code null}. Kept so every existing caller that never needed it keeps compiling unchanged.
     */
    public HumanReviewContext(
            String runId,
            String unitId,
            Path workspace,
            String reviewedRef,
            String reviewedSha,
            List<VulnerabilityWorkItem> workItems,
            List<FindingAssessment> findingAssessments,
            AnalysisRemediationGroup group,
            String decisionReason,
            List<String> companionCoordinates,
            String priorAnalysisFailureContext,
            JenkinsValidationOutcome cumulativeJenkinsValidation,
            JenkinsValidationOutcome integrationJenkinsValidation) {
        this(runId, unitId, workspace, reviewedRef, reviewedSha, workItems, findingAssessments, group,
                decisionReason, companionCoordinates, priorAnalysisFailureContext, cumulativeJenkinsValidation,
                integrationJenkinsValidation, null, null);
    }

    public boolean isGroup() {
        return group != null;
    }

    public boolean hasFindingAssessments() {
        return !findingAssessments.isEmpty();
    }

    public boolean hasPriorAnalysisFailure() {
        return priorAnalysisFailureContext != null && !priorAnalysisFailureContext.isBlank();
    }

    public boolean hasCumulativeJenkinsValidation() {
        return cumulativeJenkinsValidation != null;
    }

    public boolean hasIntegrationJenkinsValidation() {
        return integrationJenkinsValidation != null;
    }

    public boolean hasRejectedGroupOutcome() {
        return rejectedGroupOutcome != null;
    }

    public boolean hasCohortIntegrationFailure() {
        return cohortIntegrationFailure != null;
    }

    public String coordinates() {
        List<String> all = workItems.stream().map(VulnerabilityWorkItem::coordinates).toList();
        return all.size() == 1 ? all.get(0) : String.join(", ", all);
    }
}
