package com.tungsten.depbot.humanreview;

import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;

import java.util.List;

/**
 * The Human Review Engineer's answer to its six fixed questions: what is vulnerable, why, where the
 * dependency came from, what needs to change, which related dependencies to consider, and how to
 * validate a fix -- for a person to act on. Never a remediation itself.
 *
 * <p>{@code isolatedJenkinsValidation}/{@code integrationJenkinsValidation} are bot-owned, stamped onto
 * this report by {@code HumanReviewService} from its own {@link HumanReviewContext} after Claude's
 * answer is parsed -- never part of the schema Claude itself is asked to fill in, and never inferred
 * from anything Claude wrote. At most one is ever non-null for a given report: the one that actually
 * triggered this particular review (an isolated Jenkins rejection, or a cohort-level failed integration
 * review), matching whichever of {@code VulnerabilityRemediationService}'s three Jenkins-related Human
 * Review paths produced it. Both are {@code null} when Jenkins was never reached for this review at all.
 */
public record HumanReviewReport(
        String schemaVersion,
        String coordinates,
        String vulnerabilitySummary,
        String whyVulnerable,
        String dependencyOrigin,
        String recommendedChange,
        List<String> relatedDependenciesToConsider,
        String validationApproach,
        List<String> openQuestions,
        List<String> risks,
        JenkinsValidationOutcome isolatedJenkinsValidation,
        JenkinsValidationOutcome integrationJenkinsValidation,
        JenkinsValidationOutcome cumulativeJenkinsValidation) {

    /** The schema generation this application understands. */
    public static final String CURRENT_SCHEMA_VERSION = "1.0";

    public HumanReviewReport {
        schemaVersion = (schemaVersion == null || schemaVersion.isBlank())
                ? CURRENT_SCHEMA_VERSION
                : schemaVersion.strip();
        relatedDependenciesToConsider = immutable(relatedDependenciesToConsider);
        openQuestions = immutable(openQuestions);
        risks = immutable(risks);
    }

    /**
     * The shape this record had before the progressive-cumulative migration -- {@code
     * cumulativeJenkinsValidation} defaults to {@code null}. Kept so every existing caller keeps
     * compiling unchanged; new code stamps {@link #cumulativeJenkinsValidation()}, never
     * {@link #isolatedJenkinsValidation()}, which is kept only for reading old persisted reports.
     */
    public HumanReviewReport(
            String schemaVersion,
            String coordinates,
            String vulnerabilitySummary,
            String whyVulnerable,
            String dependencyOrigin,
            String recommendedChange,
            List<String> relatedDependenciesToConsider,
            String validationApproach,
            List<String> openQuestions,
            List<String> risks,
            JenkinsValidationOutcome isolatedJenkinsValidation,
            JenkinsValidationOutcome integrationJenkinsValidation) {
        this(schemaVersion, coordinates, vulnerabilitySummary, whyVulnerable, dependencyOrigin,
                recommendedChange, relatedDependenciesToConsider, validationApproach, openQuestions, risks,
                isolatedJenkinsValidation, integrationJenkinsValidation, null);
    }

    /** As {@link com.tungsten.depbot.remediation.RemediationReport#effectiveGroupJenkinsValidation()}. */
    public JenkinsValidationOutcome effectiveGroupJenkinsValidation() {
        return cumulativeJenkinsValidation != null ? cumulativeJenkinsValidation : isolatedJenkinsValidation;
    }

    private static List<String> immutable(List<String> values) {
        return values == null ? List.of() : List.copyOf(values);
    }
}
