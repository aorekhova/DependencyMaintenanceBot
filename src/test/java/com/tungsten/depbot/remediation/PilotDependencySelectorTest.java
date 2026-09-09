package com.tungsten.depbot.remediation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PilotDependencySelectorTest {

    private static LibraryRemediation library(String groupId, String artifactId, String severity) {
        return new LibraryRemediation(groupId, artifactId, "1.0", "2.0", severity, List.of("CVE-1"), null);
    }

    private static RemediationPlan planWith(
            List<LibraryRemediation> critical, List<LibraryRemediation> high,
            List<LibraryRemediation> medium, List<LibraryRemediation> low,
            List<LibraryRemediation> manualAnalysisRequired) {
        return new RemediationPlan("2026-08-05T09:00:00Z", "2026-08-05T09:00:00Z",
                RemediationPlan.CURRENT_VERSION, critical, high, medium, low, manualAnalysisRequired);
    }

    @Test
    @DisplayName("a library found in high stays in high, and the other buckets are emptied")
    void keepsTheLibraryInItsRealSeverityAndEmptiesTheRest() {
        LibraryRemediation jackson = library("com.fasterxml.jackson.core", "jackson-databind", "HIGH");
        RemediationPlan plan = planWith(
                List.of(library("g", "critical-lib", "CRITICAL")),
                List.of(jackson),
                List.of(library("g", "medium-lib", "MEDIUM")),
                List.of(library("g", "low-lib", "LOW")),
                List.of());

        RemediationPlan narrowed = PilotDependencySelector.selectOnly(
                plan, "com.fasterxml.jackson.core", "jackson-databind");

        assertEquals(List.of(), narrowed.critical());
        assertEquals(List.of(jackson), narrowed.high());
        assertEquals(List.of(), narrowed.medium());
        assertEquals(List.of(), narrowed.low());
        assertEquals(List.of(), narrowed.manualAnalysisRequired());
        assertEquals(1, narrowed.totalLibraries());
    }

    @Test
    @DisplayName("a library found in critical is kept there, not moved")
    void keepsACriticalLibraryInCritical() {
        LibraryRemediation critical = library("g", "a", "CRITICAL");
        RemediationPlan plan = planWith(List.of(critical), List.of(), List.of(), List.of(), List.of());

        RemediationPlan narrowed = PilotDependencySelector.selectOnly(plan, "g", "a");

        assertEquals(List.of(critical), narrowed.critical());
        assertTrue(narrowed.high().isEmpty());
    }

    @Test
    @DisplayName("top-level plan metadata (generatedAt, sourceReportGeneratedAt, reportVersion) is carried through")
    void carriesTopLevelMetadataThrough() {
        LibraryRemediation only = library("g", "a", "LOW");
        RemediationPlan plan = planWith(List.of(), List.of(), List.of(), List.of(only), List.of());

        RemediationPlan narrowed = PilotDependencySelector.selectOnly(plan, "g", "a");

        assertEquals(plan.generatedAt(), narrowed.generatedAt());
        assertEquals(plan.sourceReportGeneratedAt(), narrowed.sourceReportGeneratedAt());
        assertEquals(plan.reportVersion(), narrowed.reportVersion());
    }

    @Test
    @DisplayName("coordinates matching no library anywhere in the plan are rejected")
    void unknownCoordinatesAreRejected() {
        RemediationPlan plan = planWith(
                List.of(library("g", "a", "CRITICAL")), List.of(), List.of(), List.of(), List.of());

        DependencyNotFoundException e = assertThrows(DependencyNotFoundException.class,
                () -> PilotDependencySelector.selectOnly(plan, "does.not", "exist"));
        assertTrue(e.getMessage().contains("does.not:exist"), e.getMessage());
    }

    @Test
    @DisplayName("a library present only under manualAnalysisRequired cannot be piloted")
    void manualAnalysisOnlyLibraryIsRejected() {
        LibraryRemediation manual = library("g", "unclassified", "OTHER");
        RemediationPlan plan = planWith(List.of(), List.of(), List.of(), List.of(), List.of(manual));

        DependencyNotFoundException e = assertThrows(DependencyNotFoundException.class,
                () -> PilotDependencySelector.selectOnly(plan, "g", "unclassified"));
        assertTrue(e.getMessage().contains("manual analysis"), e.getMessage());
    }

    @Test
    @DisplayName("matching is by exact groupId and artifactId, not a partial or case-insensitive match")
    void matchingIsExact() {
        RemediationPlan plan = planWith(
                List.of(library("com.example", "widget", "CRITICAL")), List.of(), List.of(), List.of(), List.of());

        assertThrows(DependencyNotFoundException.class,
                () -> PilotDependencySelector.selectOnly(plan, "com.example", "Widget"));
        assertThrows(DependencyNotFoundException.class,
                () -> PilotDependencySelector.selectOnly(plan, "com.example.sub", "widget"));
    }
}
