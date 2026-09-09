package com.tungsten.depbot.publication;

import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;
import com.tungsten.depbot.jenkins.JenkinsValidationStatus;
import com.tungsten.depbot.remediation.CohortsIndex;
import com.tungsten.depbot.remediation.RemediationCohort;
import com.tungsten.depbot.remediation.RemediationReport;
import com.tungsten.depbot.validation.ValidationStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicationEligibilityTest {

    private static final String COMMIT_SHA = "abc123";
    private static final String GROUP_ID = "g-mchange";

    private static JenkinsValidationOutcome success() {
        return new JenkinsValidationOutcome(JenkinsValidationStatus.SUCCESS, "job", 1, "url",
                "base", COMMIT_SHA, "tree", 10L, "Jenkins reported result SUCCESS");
    }

    private static JenkinsValidationOutcome failure() {
        return new JenkinsValidationOutcome(JenkinsValidationStatus.FAILED, "job", 2, "url",
                "base", COMMIT_SHA, "tree", 10L, "Jenkins reported result FAILURE");
    }

    private static RemediationReport report(
            ValidationStatus dependencyStatus, ValidationStatus fullBuildStatus,
            JenkinsValidationOutcome isolated, JenkinsValidationOutcome integration) {
        return new RemediationReport("1.0", COMMIT_SHA, GROUP_ID, List.of("com.mchange:c3p0"),
                "changed", "necessary", "why", List.of("pom.xml"), "validated", List.of(),
                dependencyStatus, fullBuildStatus, isolated, integration);
    }

    private static CohortsIndex.Entry cohort(RemediationCohort.PublicationStatus status) {
        return new CohortsIndex.Entry("remediation/run1/branch", "refs/remotes/origin/hotfix-2026.1",
                "sourcesha", status, List.of(new CohortsIndex.Commit(GROUP_ID, COMMIT_SHA, "path")));
    }

    @Test
    @DisplayName("a cohort with every bot-owned fact PASSED/SUCCESS is eligible")
    void fullyPassingCohortIsEligible() {
        RemediationReport report = report(ValidationStatus.PASSED, ValidationStatus.PASSED, success(), success());
        EligibilityResult result = PublicationEligibility.evaluate(
                cohort(RemediationCohort.PublicationStatus.READY_TO_PUBLISH), Map.of(COMMIT_SHA, report));

        assertTrue(result.eligible(), result.reason());
    }

    @Test
    @DisplayName("cohort publicationStatus other than READY_TO_PUBLISH is never eligible")
    void nonReadyToPublishStatusIsIneligible() {
        RemediationReport report = report(ValidationStatus.PASSED, ValidationStatus.PASSED, success(), success());
        EligibilityResult result = PublicationEligibility.evaluate(
                cohort(RemediationCohort.PublicationStatus.PUSHED), Map.of(COMMIT_SHA, report));

        assertFalse(result.eligible());
        assertTrue(result.reason().contains("READY_TO_PUBLISH"), result.reason());
    }

    @Test
    @DisplayName("a missing RemediationReport for a commit is never eligible")
    void missingReportIsIneligible() {
        EligibilityResult result = PublicationEligibility.evaluate(
                cohort(RemediationCohort.PublicationStatus.READY_TO_PUBLISH), Map.of());

        assertFalse(result.eligible());
        assertTrue(result.reason().contains(COMMIT_SHA), result.reason());
    }

    @Test
    @DisplayName("dependency validation not PASSED is never eligible")
    void dependencyValidationNotPassedIsIneligible() {
        RemediationReport report = report(ValidationStatus.FAILED, ValidationStatus.PASSED, success(), success());
        EligibilityResult result = PublicationEligibility.evaluate(
                cohort(RemediationCohort.PublicationStatus.READY_TO_PUBLISH), Map.of(COMMIT_SHA, report));

        assertFalse(result.eligible());
        assertTrue(result.reason().contains("dependency validation"), result.reason());
    }

    @Test
    @DisplayName("the full local build not PASSED is never eligible")
    void fullBuildNotPassedIsIneligible() {
        RemediationReport report = report(ValidationStatus.PASSED, ValidationStatus.FAILED, success(), success());
        EligibilityResult result = PublicationEligibility.evaluate(
                cohort(RemediationCohort.PublicationStatus.READY_TO_PUBLISH), Map.of(COMMIT_SHA, report));

        assertFalse(result.eligible());
        assertTrue(result.reason().contains("full local build"), result.reason());
    }

    @Test
    @DisplayName("a missing or unsuccessful isolated Jenkins validation is never eligible")
    void missingOrFailedIsolatedJenkinsIsIneligible() {
        EligibilityResult missing = PublicationEligibility.evaluate(
                cohort(RemediationCohort.PublicationStatus.READY_TO_PUBLISH),
                Map.of(COMMIT_SHA, report(ValidationStatus.PASSED, ValidationStatus.PASSED, null, success())));
        assertFalse(missing.eligible());
        assertTrue(missing.reason().contains("Jenkins validation did not succeed"), missing.reason());

        EligibilityResult failed = PublicationEligibility.evaluate(
                cohort(RemediationCohort.PublicationStatus.READY_TO_PUBLISH),
                Map.of(COMMIT_SHA, report(ValidationStatus.PASSED, ValidationStatus.PASSED, failure(), success())));
        assertFalse(failed.eligible());
        assertTrue(failed.reason().contains("Jenkins validation did not succeed"), failed.reason());
    }

    @Test
    @DisplayName("a missing or unsuccessful final integration Jenkins validation is never eligible")
    void missingOrFailedIntegrationJenkinsIsIneligible() {
        EligibilityResult missing = PublicationEligibility.evaluate(
                cohort(RemediationCohort.PublicationStatus.READY_TO_PUBLISH),
                Map.of(COMMIT_SHA, report(ValidationStatus.PASSED, ValidationStatus.PASSED, success(), null)));
        assertFalse(missing.eligible());
        assertTrue(missing.reason().contains("final integration Jenkins"), missing.reason());

        EligibilityResult failed = PublicationEligibility.evaluate(
                cohort(RemediationCohort.PublicationStatus.READY_TO_PUBLISH),
                Map.of(COMMIT_SHA, report(ValidationStatus.PASSED, ValidationStatus.PASSED, success(), failure())));
        assertFalse(failed.eligible());
        assertTrue(failed.reason().contains("final integration Jenkins"), failed.reason());
    }

    /** Every other test in this file builds a report through the pre-cumulative-migration 14-arg
     *  constructor (populating only {@code isolatedJenkinsValidation}) -- these two additionally lock
     *  in both ends of the {@code effectiveGroupJenkinsValidation()} fallback the cumulative migration
     *  introduced, so eligibility for a brand-new run and eligibility for an old, already-persisted run
     *  are both independently verified rather than only the legacy shape being exercised. */

    @Test
    @DisplayName("a freshly-built report for a new (cumulative) run is eligible via cumulativeJenkinsValidation "
            + "alone, with isolatedJenkinsValidation left null")
    void newRunsPopulateCumulativeNotIsolatedJenkinsField() {
        RemediationReport report = new RemediationReport("1.0", COMMIT_SHA, GROUP_ID, List.of("com.mchange:c3p0"),
                "changed", "necessary", "why", List.of("pom.xml"), "validated", List.of(),
                ValidationStatus.PASSED, ValidationStatus.PASSED, null, success(), "acceptedBaseSha", success());

        assertEquals(success(), report.effectiveGroupJenkinsValidation());
        assertTrue(report.jenkinsValidated());
        EligibilityResult result = PublicationEligibility.evaluate(
                cohort(RemediationCohort.PublicationStatus.READY_TO_PUBLISH), Map.of(COMMIT_SHA, report));
        assertTrue(result.eligible(), result.reason());
    }

    @Test
    @DisplayName("an old-shaped report carrying only the legacy isolatedJenkinsValidation field -- with no "
            + "cumulativeJenkinsValidation at all -- still publishes via the fallback")
    void oldShapedReportWithOnlyIsolatedFieldStillPublishes() {
        RemediationReport report = report(ValidationStatus.PASSED, ValidationStatus.PASSED, success(), success());

        assertEquals(success(), report.effectiveGroupJenkinsValidation());
        EligibilityResult result = PublicationEligibility.evaluate(
                cohort(RemediationCohort.PublicationStatus.READY_TO_PUBLISH), Map.of(COMMIT_SHA, report));
        assertTrue(result.eligible(), result.reason());
    }
}
