package com.tungsten.depbot.remediation;

import com.tungsten.depbot.assessment.AnalysisRemediationGroup;
import com.tungsten.depbot.assessment.AssessmentConclusion;
import com.tungsten.depbot.assessment.AutomationSafety;
import com.tungsten.depbot.assessment.BatchAnalysis;
import com.tungsten.depbot.assessment.FindingAssessment;
import com.tungsten.depbot.assessment.ImpactScore;
import com.tungsten.depbot.assessment.PlannedChangeType;
import com.tungsten.depbot.assessment.PlannedDependencyChange;
import com.tungsten.depbot.assessment.VulnerabilityWorkItem;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Focused regression coverage for the one check {@link RemediationGroupValidator} adds on top of its
 * pre-existing "unknown member coordinates" check: a fresh analysis's own metadata contract requires
 * {@code plannedChanges} whenever a narrative {@code implementationPlan} is present, since only
 * {@code plannedChanges} is objectively verifiable downstream. This is deliberately stricter than
 * partial-analysis salvage, which is allowed to route a group through on direction and sourceRef alone
 * -- see {@code PartialAnalysisFallbackTest} for that distinct, more tolerant behaviour.
 */
class RemediationGroupValidatorTest {

    private static final String COORDINATES = "com.example:artifact-a";

    @Test
    @DisplayName("a group with a narrative implementationPlan but empty plannedChanges is invalid for a "
            + "fresh analysis")
    void narrativePlanWithoutPlannedChangesIsInvalid() {
        AnalysisRemediationGroup group = groupWith(List.of("Bump to a fixed version."), List.of());

        GroupingValidationOutcome outcome = RemediationGroupValidator.validate(
                analysisWith(group), List.of(workItem()));

        assertTrue(outcome.validGroups().isEmpty(), "the group must not be treated as valid");
        assertTrue(outcome.invalidGroupReasons().containsKey(COORDINATES));
        String reason = outcome.invalidGroupReasons().get(COORDINATES);
        assertTrue(reason.contains("plannedChanges"), "reason must name the missing field: " + reason);
    }

    @Test
    @DisplayName("a group with both implementationPlan and plannedChanges is valid")
    void narrativePlanWithPlannedChangesIsValid() {
        PlannedDependencyChange change = new PlannedDependencyChange(
                "com.example:artifact-a", "1.0", "1.1", "pom.xml", PlannedChangeType.VERSION_BUMP,
                "raise the version");
        AnalysisRemediationGroup group = groupWith(List.of("Bump to a fixed version."), List.of(change));

        GroupingValidationOutcome outcome = RemediationGroupValidator.validate(
                analysisWith(group), List.of(workItem()));

        assertEquals(1, outcome.validGroups().size());
        assertTrue(outcome.invalidGroupReasons().isEmpty());
    }

    @Test
    @DisplayName("a group with no narrative implementationPlan at all is not caught by this check "
            + "(that is hasEstablishedRemediationDirection()'s own concern, not the validator's)")
    void noImplementationPlanAtAllPassesThisCheck() {
        AnalysisRemediationGroup group = groupWith(List.of(), List.of());

        GroupingValidationOutcome outcome = RemediationGroupValidator.validate(
                analysisWith(group), List.of(workItem()));

        assertEquals(1, outcome.validGroups().size());
        assertTrue(outcome.invalidGroupReasons().isEmpty());
    }

    private static AnalysisRemediationGroup groupWith(
            List<String> implementationPlan, List<PlannedDependencyChange> plannedChanges) {
        return new AnalysisRemediationGroup(
                "g-a",
                List.of(COORDINATES),
                List.of(),
                "single-library remediation",
                "main",
                null,
                null,
                null,
                "1.0",
                "bump the dependency",
                "1.1",
                List.of("pom.xml"),
                ImpactScore.of(6),
                "remotely exploitable",
                AutomationSafety.AUTOMATIC_ALLOWED,
                "no reason to withhold automation",
                implementationPlan,
                List.of(),
                plannedChanges);
    }

    private static BatchAnalysis analysisWith(AnalysisRemediationGroup group) {
        FindingAssessment finding = new FindingAssessment(
                COORDINATES, List.of("CVE-2026-X"), "summary", AssessmentConclusion.REMEDIATION_REQUIRED,
                group.groupId(), List.of(), List.of());
        return new BatchAnalysis(BatchAnalysis.CURRENT_SCHEMA_VERSION, List.of(finding), List.of(group));
    }

    private static VulnerabilityWorkItem workItem() {
        return new VulnerabilityWorkItem("com.example", "artifact-a", "1.0", "CRITICAL", "1.1", List.of());
    }
}
