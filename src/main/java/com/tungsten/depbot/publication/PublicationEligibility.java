package com.tungsten.depbot.publication;

import com.tungsten.depbot.remediation.CohortsIndex;
import com.tungsten.depbot.remediation.RemediationCohort;
import com.tungsten.depbot.remediation.RemediationReport;
import com.tungsten.depbot.validation.ValidationStatus;

import java.util.Map;
import java.util.Objects;

/**
 * The single, explicit, Java-owned predicate deciding whether a cohort may be published -- re-derived
 * from the same bot-owned structured fields {@code VulnerabilityRemediationService} already used to
 * decide {@link RemediationCohort.PublicationStatus#READY_TO_PUBLISH}, never restored by heuristics over
 * Claude's own prose.
 *
 * <p>Re-checked here on purpose, not merely trusted from {@code cohorts.json}'s own {@code
 * publicationStatus}: publication can run as a separate, later step (a retried {@code publish}), reading
 * files a {@code remediate} run wrote earlier and possibly inspected or edited by hand in between. Every
 * one of the checks below is cheap and already available in the same {@link RemediationReport} objects
 * {@code GitLabPublicationService} loads anyway to build a commit's own report comment -- this class
 * only adds the explicit gate before anything is published, not a second source of the facts themselves.
 */
public final class PublicationEligibility {

    private PublicationEligibility() {
    }

    /**
     * @param reportsByCommitSha every commit in {@code cohort} must have an entry here, keyed by its own
     *                           {@code commitSha} -- a missing entry is itself an ineligibility reason,
     *                           never silently skipped
     */
    public static EligibilityResult evaluate(
            CohortsIndex.Entry cohort, Map<String, RemediationReport> reportsByCommitSha) {
        Objects.requireNonNull(cohort, "cohort");
        Objects.requireNonNull(reportsByCommitSha, "reportsByCommitSha");

        if (cohort.publicationStatus() != RemediationCohort.PublicationStatus.READY_TO_PUBLISH) {
            return EligibilityResult.ineligible(
                    "cohort publicationStatus is " + cohort.publicationStatus() + ", not READY_TO_PUBLISH");
        }

        for (CohortsIndex.Commit commit : cohort.commits()) {
            RemediationReport report = reportsByCommitSha.get(commit.commitSha());
            if (report == null) {
                return EligibilityResult.ineligible("no RemediationReport was found for commit "
                        + commit.commitSha() + " (group " + commit.groupId() + ")");
            }
            if (report.dependencyValidationStatus() != ValidationStatus.PASSED) {
                return EligibilityResult.ineligible("group " + commit.groupId()
                        + "'s dependency validation is " + report.dependencyValidationStatus()
                        + ", not PASSED");
            }
            if (!report.fullyBuildValidated()) {
                return EligibilityResult.ineligible("group " + commit.groupId()
                        + "'s full local build is not PASSED (" + report.fullBuildValidationStatus() + ")");
            }
            if (report.effectiveGroupJenkinsValidation() == null || !report.effectiveGroupJenkinsValidation().succeeded()) {
                return EligibilityResult.ineligible(
                        "group " + commit.groupId() + "'s own (cumulative or, for an older run, isolated) "
                                + "Jenkins validation did not succeed");
            }
            if (report.integrationJenkinsValidation() == null
                    || !report.integrationJenkinsValidation().succeeded()) {
                return EligibilityResult.ineligible("group " + commit.groupId()
                        + "'s final integration Jenkins validation did not succeed");
            }
        }

        return EligibilityResult.allowed();
    }
}
