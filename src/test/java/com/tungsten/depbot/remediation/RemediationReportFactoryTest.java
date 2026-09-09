package com.tungsten.depbot.remediation;

import com.tungsten.depbot.assessment.Assessments;
import com.tungsten.depbot.assessment.AnalysisRemediationGroup;
import com.tungsten.depbot.implementation.ImplementationGroupMember;
import com.tungsten.depbot.implementation.ImplementationConclusion;
import com.tungsten.depbot.implementation.ImplementationReport;
import com.tungsten.depbot.validation.ValidationOutcome;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fast regression tests for {@link RemediationReportFactory} -- in particular, Bug 1 from pilot
 * {@code 20260909-061155-6ca4db}: {@code validationPerformedItems} must keep every one of Claude's own
 * {@code ImplementationReport.validationPerformed()} entries as its own structured list item, never
 * re-flattened into a single {@code "Claude reported: A; B; C"} item before the renderer ever sees it.
 */
class RemediationReportFactoryTest {

    private static ImplementationReport implementationReport(List<String> validationPerformed) {
        return new ImplementationReport(
                "1.0", "com.example:artifact", ImplementationConclusion.COMPLETED,
                "raised the version to close the CVE", "the dependency was present as described",
                List.of("raised the version property"), List.of(), validationPerformed, List.of(), List.of());
    }

    private static AnalysisRemediationGroup group() {
        return Assessments.remediationGroup(2);
    }

    private static List<ImplementationGroupMember> members() {
        return List.of(new ImplementationGroupMember(Assessments.workItem(),
                Assessments.remediationRequiredFinding()));
    }

    @Test
    @DisplayName("each of Claude's own validationPerformed entries becomes its own structured "
            + "validationPerformedItems entry, never re-joined into one item")
    void eachClaudeValidationItemStaysSeparate() {
        ImplementationReport report = implementationReport(List.of(
                "dependency tree resolved cleanly", "reactor tests passed", "packaged WAR inspected"));

        RemediationReport built = RemediationReportFactory.build(
                group(), members(), report, "commitsha123", "", null, null, Map.of(), null, null);

        List<String> claudeItems = built.validationPerformedItems().stream()
                .filter(item -> item.startsWith("Claude: "))
                .toList();
        assertEquals(3, claudeItems.size(), built.validationPerformedItems().toString());
        assertTrue(claudeItems.contains("Claude: dependency tree resolved cleanly"), claudeItems.toString());
        assertTrue(claudeItems.contains("Claude: reactor tests passed"), claudeItems.toString());
        assertTrue(claudeItems.contains("Claude: packaged WAR inspected"), claudeItems.toString());
    }

    @Test
    @DisplayName("no validationPerformedItems entry is a \"; \"-joined re-flattening of the others")
    void noItemIsAJoinedReflattening() {
        ImplementationReport report = implementationReport(List.of("check A", "check B", "check C"));

        RemediationReport built = RemediationReportFactory.build(
                group(), members(), report, "commitsha123", "", null, null, Map.of(), null, null);

        for (String item : built.validationPerformedItems()) {
            assertFalse(item.contains("check A; check B"), item);
            assertFalse(item.startsWith("Claude reported:"), item);
        }
    }

    @Test
    @DisplayName("the dependency-resolution gate and full-build outcomes remain their own additional "
            + "items, distinct from Claude's own checks")
    void gateAndBuildOutcomesAreSeparateItems() {
        ImplementationReport report = implementationReport(List.of("check A"));
        ValidationOutcome gate = ValidationOutcome.passed("resolved cleanly", List.of(), "output");
        ValidationOutcome build = ValidationOutcome.passed(
                "The full build succeeded: mvn.cmd -B clean package exited 0.",
                List.of("mvn.cmd", "-B", "clean", "package"), "output");

        RemediationReport built = RemediationReportFactory.build(
                group(), members(), report, "commitsha123", "", gate, build, Map.of(), null, null);

        assertEquals(3, built.validationPerformedItems().size(), built.validationPerformedItems().toString());
        assertTrue(built.validationPerformedItems().get(0).equals("Claude: check A"));
        assertTrue(built.validationPerformedItems().get(1).startsWith("Dependency-resolution gate: "));
        assertTrue(built.validationPerformedItems().get(2).startsWith("Full build ("));
    }

    @Test
    @DisplayName("JSON-compatibility guard: the legacy, flattened validationPerformed string field is "
            + "still populated exactly as before")
    void legacyFlattenedStringFieldStillPopulated() {
        ImplementationReport report = implementationReport(List.of("check A", "check B"));

        RemediationReport built = RemediationReportFactory.build(
                group(), members(), report, "commitsha123", "", null, null, Map.of(), null, null);

        assertTrue(built.validationPerformed().contains("check A; check B"), built.validationPerformed());
    }
}
