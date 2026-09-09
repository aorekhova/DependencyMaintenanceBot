package com.tungsten.depbot.remediation;

import com.tungsten.depbot.assessment.RemediationVerdict;
import com.tungsten.depbot.git.SourceRefVerification;
import com.tungsten.depbot.humanreview.HumanReviewOutcome;
import com.tungsten.depbot.humanreview.HumanReviewReport;
import com.tungsten.depbot.implementation.ImplementationOutcome;
import com.tungsten.depbot.implementation.RemediationImplementationService;

import java.util.ArrayList;
import java.util.List;

/** Flattens each library's staged outcome into the run summary's index form. */
public final class RemediationSummaryBuilder {

    private RemediationSummaryBuilder() {
    }

    public static RemediationSummary build(
            String runId,
            String generatedAt,
            String model,
            String repoPath,
            String dependencyFilter,
            List<VulnerabilityRemediationOutcome> outcomes) {

        List<RemediationSummaryEntry> entries = new ArrayList<>();
        for (VulnerabilityRemediationOutcome outcome : outcomes) {
            entries.add(entryFor(outcome));
        }
        return new RemediationSummary(runId, generatedAt, RemediationSummary.CURRENT_VERSION, model,
                repoPath, dependencyFilter, entries);
    }

    private static RemediationSummaryEntry entryFor(VulnerabilityRemediationOutcome outcome) {
        SourceRefVerification verification = outcome.sourceRefVerification();
        ImplementationOutcome implementation = outcome.implementation();
        HumanReviewOutcome humanReview = outcome.humanReviewOutcome();
        HumanReviewReport humanReviewReport = humanReview == null ? null : humanReview.report();

        return new RemediationSummaryEntry(
                outcome.coordinates(),
                outcome.unitId(),
                outcome.reachedStage(),

                outcome.conclusion(),
                outcome.impactScore() == null ? null : outcome.impactScore().value(),
                outcome.verdict(),
                outcome.automationSafety(),
                outcome.automationSafetyReason(),

                verification == null ? null : verification.requestedRef(),
                verification == null ? null : verification.resolvedRef(),
                verification == null ? null : verification.resolvedSha(),
                verification == null ? null : verification.claimedSha(),
                verification == null ? null : verification.claimMatched(),

                outcome.branchName(),
                implementation == null || implementation.report() == null
                        ? null : implementation.report().conclusion(),
                implementation == null || implementation.validation() == null
                        ? null : implementation.validation().status(),
                implementation == null || implementation.validation() == null
                        ? null : implementation.validation().reason(),
                implementation == null || implementation.fullBuildValidation() == null
                        ? null : implementation.fullBuildValidation().status(),
                implementation == null || implementation.fullBuildValidation() == null
                        ? null : implementation.fullBuildValidation().reason(),
                implementation == null || implementation.fullBuildValidation() == null
                        ? null : implementation.implementationDirectory()
                                .resolve(RemediationImplementationService.FULL_BUILD_OUTPUT_FILE).toString(),
                implementation == null ? null : implementation.disposition(),
                implementation == null ? null : implementation.change().commitSha(),

                outcome.remediationReport() == null ? null : outcome.remediationReport().groupId(),
                // effectiveGroupJenkinsValidation() -- prefers the new cumulative field, falls back to
                // the legacy isolated field for an older run -- see RemediationReport's own javadoc.
                outcome.remediationReport() == null ? null : outcome.remediationReport().effectiveGroupJenkinsValidation(),
                outcome.remediationReport() == null ? null : outcome.remediationReport().integrationJenkinsValidation(),

                outcome.stopReason(),
                // The analysis is now one whole-batch call, not one per unit -- see the run's own
                // analysis-attempt.json/analysis.json under the run directory, not a per-entry path.
                null,
                implementation == null ? null : implementation.implementationDirectory().toString(),

                humanReview == null ? null : humanReview.humanReviewDirectory().toString(),
                humanReview == null ? null : humanReview.hasReport(),
                humanReviewReport == null ? null : humanReviewReport.vulnerabilitySummary(),
                humanReviewReport == null ? null : humanReviewReport.whyVulnerable(),
                humanReviewReport == null ? null : humanReviewReport.dependencyOrigin(),
                humanReviewReport == null ? null : humanReviewReport.recommendedChange(),
                humanReviewReport == null ? null : humanReviewReport.relatedDependenciesToConsider(),
                humanReviewReport == null ? null : humanReviewReport.validationApproach(),
                humanReviewReport == null ? null : humanReviewReport.openQuestions(),
                classifyOutcomeState(outcome));
    }

    /**
     * What ultimately became of this library's group -- see {@link GroupOutcomeState}'s own javadoc for
     * why an automatic attempt that was rejected but still produced a Human Review report must never be
     * indistinguishable from one where even that could not be produced. Mirrors the same exclusion
     * structure {@link RemediationSummaryEntry#needsAHuman()} already uses, split one level further by
     * whether a report exists.
     */
    private static GroupOutcomeState classifyOutcomeState(VulnerabilityRemediationOutcome outcome) {
        if (outcome.restore() != null && !outcome.restore().restored()) {
            return GroupOutcomeState.UNSAFE_STATE;
        }
        if (outcome.reachedStage() == RemediationStage.ASSESSMENT_INCOMPLETE) {
            return GroupOutcomeState.ANALYSIS_INCOMPLETE;
        }
        if (outcome.verdict() == RemediationVerdict.NO_ACTION_REQUIRED) {
            return GroupOutcomeState.NO_ACTION_REQUIRED;
        }
        if (outcome.humanReviewRequired()) {
            return GroupOutcomeState.HUMAN_REVIEW_REQUIRED;
        }
        if (outcome.committed()) {
            return GroupOutcomeState.ACCEPTED;
        }
        boolean hasReport = outcome.humanReviewOutcome() != null && outcome.humanReviewOutcome().hasReport();
        return hasReport ? GroupOutcomeState.AUTOMATIC_REJECTED_WITH_REPORT : GroupOutcomeState.AUTOMATIC_REJECTED_NO_REPORT;
    }
}
