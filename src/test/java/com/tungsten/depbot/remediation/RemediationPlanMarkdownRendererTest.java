package com.tungsten.depbot.remediation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemediationPlanMarkdownRendererTest {

    private final RemediationPlanMarkdownRenderer renderer = new RemediationPlanMarkdownRenderer();

    private static RemediationPlan emptyPlan() {
        return new RemediationPlan("2026-08-04T10:00:00Z", "2026-08-04T09:00:00Z",
                RemediationPlan.CURRENT_VERSION, List.of(), List.of(), List.of(), List.of(), List.of());
    }

    @Test
    @DisplayName("all five sections are present even when the plan is empty")
    void allFiveSectionsArePresentWhenEmpty() {
        String markdown = renderer.render(emptyPlan());

        assertTrue(markdown.contains("## Critical"));
        assertTrue(markdown.contains("## High"));
        assertTrue(markdown.contains("## Medium"));
        assertTrue(markdown.contains("## Low"));
        assertTrue(markdown.contains("## Manual analysis required"));
    }

    @Test
    @DisplayName("an empty section states explicitly that it has no libraries")
    void emptySectionStatesItExplicitly() {
        String markdown = renderer.render(emptyPlan());
        long occurrences = markdown.lines().filter(RemediationPlanMarkdownRenderer.NO_LIBRARIES::equals).count();

        assertEquals(5, occurrences);
    }

    @Test
    @DisplayName("a library entry renders its coordinates, versions and CVE list in a table row")
    void libraryEntryRendersAsTableRow() {
        LibraryRemediation entry = new LibraryRemediation(
                "org.bouncycastle", "bcprov-jdk18on", "1.84", "1.85", "CRITICAL",
                List.of("CVE-2026-1", "CVE-2026-2"), null);
        RemediationPlan plan = new RemediationPlan("2026-08-04T10:00:00Z", "2026-08-04T09:00:00Z",
                RemediationPlan.CURRENT_VERSION, List.of(entry), List.of(), List.of(), List.of(), List.of());

        String markdown = renderer.render(plan);

        assertTrue(markdown.contains("org.bouncycastle:bcprov-jdk18on"));
        assertTrue(markdown.contains("1.84"));
        assertTrue(markdown.contains("1.85"));
        assertTrue(markdown.contains("CVE-2026-1, CVE-2026-2"));
    }

    @Test
    @DisplayName("a pipe character inside a CVE list is escaped so the table stays rectangular")
    void pipeInCellIsEscaped() {
        LibraryRemediation entry = new LibraryRemediation(
                "g", "a", "1.0", "2.0", "HIGH", List.of("CVE|INJECTED"), null);
        RemediationPlan plan = new RemediationPlan("2026-08-04T10:00:00Z", "2026-08-04T09:00:00Z",
                RemediationPlan.CURRENT_VERSION, List.of(), List.of(entry), List.of(), List.of(), List.of());

        String markdown = renderer.render(plan);
        String headerRow = "| Library | Current version | Target version | CVEs |";
        int headerPipes = (int) headerRow.chars().filter(c -> c == '|').count();

        markdown.lines()
                .filter(line -> line.contains("CVE") && line.startsWith("|"))
                .forEach(line -> {
                    // Strip escaped pipes first: an escaped "\|" inside a cell is content, not a
                    // column separator, and must not be counted as one.
                    long unescapedPipes = line.replace("\\|", "").chars().filter(c -> c == '|').count();
                    assertEquals(headerPipes, (int) unescapedPipes,
                            "row must have the same number of unescaped pipes as the header: " + line);
                });
    }

    @Test
    @DisplayName("missing target version renders as MANUAL_ANALYSIS_REQUIRED, not blank")
    void manualAnalysisRequiredIsShownInTable() {
        LibraryRemediation entry = new LibraryRemediation(
                "g", "a", "1.0", TargetVersionResolver.MANUAL_ANALYSIS_REQUIRED, "OTHER", List.of("CVE-1"), null);
        RemediationPlan plan = new RemediationPlan("2026-08-04T10:00:00Z", "2026-08-04T09:00:00Z",
                RemediationPlan.CURRENT_VERSION, List.of(), List.of(), List.of(), List.of(), List.of(entry));

        assertTrue(renderer.render(plan).contains(TargetVersionResolver.MANUAL_ANALYSIS_REQUIRED));
    }

    @Test
    @DisplayName("a manual-analysis reason is rendered right under its entry's table row")
    void manualAnalysisReasonIsShownUnderItsRow() {
        String reason = "Mend's fix candidates that close every CVE (2.18.9, 2.21.5, 2.22.1) are all at or "
                + "below the current version 2.22.0 -- no forward fix is available, so this cannot be "
                + "upgraded automatically.";
        LibraryRemediation entry = new LibraryRemediation(
                "com.fasterxml.jackson.core", "jackson-databind", "2.22.0",
                TargetVersionResolver.MANUAL_ANALYSIS_REQUIRED, "MEDIUM", List.of("CVE-1"), reason);
        RemediationPlan plan = new RemediationPlan("2026-08-04T10:00:00Z", "2026-08-04T09:00:00Z",
                RemediationPlan.CURRENT_VERSION, List.of(), List.of(), List.of(), List.of(), List.of(entry));

        String markdown = renderer.render(plan);
        assertTrue(markdown.contains("Reason: " + reason), markdown);
    }

    @Test
    @DisplayName("an entry with no manual-analysis reason renders no Reason line at all")
    void noReasonLineWhenReasonIsNull() {
        LibraryRemediation entry = new LibraryRemediation(
                "org.bouncycastle", "bcprov-jdk18on", "1.84", "1.85", "CRITICAL", List.of("CVE-1"), null);
        RemediationPlan plan = new RemediationPlan("2026-08-04T10:00:00Z", "2026-08-04T09:00:00Z",
                RemediationPlan.CURRENT_VERSION, List.of(entry), List.of(), List.of(), List.of(), List.of());

        assertTrue(renderer.render(plan).lines().noneMatch(line -> line.contains("Reason:")));
    }
}
