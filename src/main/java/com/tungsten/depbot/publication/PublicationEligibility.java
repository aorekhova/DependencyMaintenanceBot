package com.tungsten.depbot.publication;

import com.tungsten.depbot.remediation.CohortsIndex;
import com.tungsten.depbot.remediation.RemediationReport;
import com.tungsten.depbot.validation.ValidationStatus;

import java.util.Objects;

/**
 * The single, explicit, Java-owned predicate deciding whether ONE GROUP's commit may be published --
 * re-derived from the same bot-owned structured fields {@code VulnerabilityRemediationService} already
 * used, never restored by heuristics over Claude's own prose.
 *
 * <p><strong>Deliberately per-commit, with no cohort-wide gate layered on top.</strong> A cohort sharing
 * one branch can combine several groups; one group's own failure (never committed at all, so it never even
 * reaches this method) must never veto a sibling's independently-earned eligibility, and the one check that
 * genuinely is about the whole assembled branch -- final integration Jenkins -- is itself recorded on
 * every accepted group's own {@link RemediationReport}, so checking it per-commit here still applies it
 * correctly to every group it actually concerns, without a separate whole-cohort short-circuit that could
 * hide which specific group is actually ineligible and why.
 *
 * <p>Re-checked here on purpose, not merely trusted from {@code cohorts.json}: publication can run as a
 * separate, later step (a retried {@code publish}), reading files a {@code remediate} run wrote earlier and
 * possibly inspected or edited by hand in between. Every one of the checks below is cheap and already
 * available in the same {@link RemediationReport} object {@code GitLabPublicationService} loads anyway to
 * build a commit's own report comment -- this class only adds the explicit gate before anything is
 * published, not a second source of the facts themselves.
 */
public final class PublicationEligibility {

    private PublicationEligibility() {
    }

    public static EligibilityResult evaluate(CohortsIndex.Commit commit, RemediationReport report) {
        Objects.requireNonNull(commit, "commit");
        if (report == null) {
            return EligibilityResult.ineligible("no RemediationReport was found for commit "
                    + commit.commitSha() + " (group " + commit.groupId() + ")");
        }

        if (report.dependencyValidationStatus() != ValidationStatus.PASSED) {
            return EligibilityResult.ineligible("group " + commit.groupId()
                    + "'s dependency validation is " + report.dependencyValidationStatus() + ", not PASSED");
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

        return EligibilityResult.allowed();
    }
}
