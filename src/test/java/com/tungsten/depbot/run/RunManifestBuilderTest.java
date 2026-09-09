package com.tungsten.depbot.run;

import com.tungsten.depbot.git.CreatedBranch;
import com.tungsten.depbot.remediation.LibraryRemediation;
import com.tungsten.depbot.remediation.RemediationPlan;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RunManifestBuilderTest {

    private static final Path RUNS_ROOT = Path.of("reports", "runs");
    private static final String WORKSPACE_PATH = "/repo";

    private static LibraryRemediation library(String artifactId, String severity) {
        return new LibraryRemediation("g", artifactId, "1.0", "2.0", severity, List.of("CVE-1", "CVE-2"), null);
    }

    private static RemediationPlan planWith(
            List<LibraryRemediation> critical, List<LibraryRemediation> high,
            List<LibraryRemediation> medium, List<LibraryRemediation> low,
            List<LibraryRemediation> manualAnalysisRequired) {
        return new RemediationPlan("2026-08-04T09:00:00Z", "2026-08-04T09:00:00Z",
                RemediationPlan.CURRENT_VERSION, critical, high, medium, low, manualAnalysisRequired);
    }

    private static CreatedBranch branch(String group) {
        return new CreatedBranch(group, "remediation/run1/" + group);
    }

    @Test
    @DisplayName("one unit is produced per library, carrying the group's branch and the shared workspace path")
    void producesOneUnitPerLibraryWithGroupBranchAndWorkspace() {
        RemediationPlan plan = planWith(List.of(library("a", "CRITICAL")), List.of(), List.of(), List.of(), List.of());

        RunManifest manifest = RunManifestBuilder.build(
                RUNS_ROOT, "run1", "2026-08-04T10:00:00Z", "sha123", plan, List.of(branch("critical")), WORKSPACE_PATH);

        assertEquals(1, manifest.units().size());
        RemediationUnit unit = manifest.units().get(0);
        assertEquals("run1", unit.runId());
        assertEquals("CRITICAL", unit.severity());
        assertEquals("g", unit.groupId());
        assertEquals("a", unit.artifactId());
        assertEquals("1.0", unit.currentVersion());
        assertEquals("2.0", unit.targetVersion());
        assertEquals(List.of("CVE-1", "CVE-2"), unit.vulnerabilityIds());
        assertEquals("remediation/run1/critical", unit.branch());
        assertEquals(WORKSPACE_PATH, unit.workspacePath());
        assertEquals(RemediationUnit.PENDING_STATUS, unit.status());
        assertEquals(0, unit.attempts());
        assertTrue(unit.taskFile().contains("critical"));
        assertTrue(unit.taskFile().contains("g__a.md"));
    }

    @Test
    @DisplayName("multiple libraries in the same group all share that group's branch and the workspace path")
    void multipleLibrariesInSameGroupShareBranchAndWorkspace() {
        RemediationPlan plan = planWith(
                List.of(library("a", "CRITICAL"), library("b", "CRITICAL")), List.of(), List.of(), List.of(), List.of());

        RunManifest manifest = RunManifestBuilder.build(
                RUNS_ROOT, "run1", "2026-08-04T10:00:00Z", "sha123", plan, List.of(branch("critical")), WORKSPACE_PATH);

        assertEquals(2, manifest.units().size());
        assertEquals(manifest.units().get(0).branch(), manifest.units().get(1).branch());
        assertEquals(manifest.units().get(0).workspacePath(), manifest.units().get(1).workspacePath());
    }

    @Test
    @DisplayName("libraries in different groups all share the same workspace path")
    void differentGroupsShareTheSameWorkspacePath() {
        RemediationPlan plan = planWith(
                List.of(library("a", "CRITICAL")), List.of(library("b", "HIGH")), List.of(), List.of(), List.of());

        RunManifest manifest = RunManifestBuilder.build(
                RUNS_ROOT, "run1", "2026-08-04T10:00:00Z", "sha123", plan,
                List.of(branch("critical"), branch("high")), WORKSPACE_PATH);

        assertEquals(2, manifest.units().size());
        assertEquals(WORKSPACE_PATH, manifest.units().get(0).workspacePath());
        assertEquals(WORKSPACE_PATH, manifest.units().get(1).workspacePath());
    }

    @Test
    @DisplayName("a group with libraries but no matching branch contributes no units")
    void groupWithoutMatchingBranchContributesNoUnits() {
        RemediationPlan plan = planWith(List.of(library("a", "CRITICAL")), List.of(), List.of(), List.of(), List.of());

        RunManifest manifest = RunManifestBuilder.build(
                RUNS_ROOT, "run1", "2026-08-04T10:00:00Z", "sha123", plan, List.of(), WORKSPACE_PATH);

        assertTrue(manifest.units().isEmpty());
    }

    @Test
    @DisplayName("manualAnalysisRequired is carried through unchanged and never becomes a unit")
    void manualAnalysisRequiredIsCarriedThroughButNeverBecomesAUnit() {
        LibraryRemediation manual = library("m", "OTHER");
        RemediationPlan plan = planWith(List.of(), List.of(), List.of(), List.of(), List.of(manual));

        RunManifest manifest = RunManifestBuilder.build(
                RUNS_ROOT, "run1", "2026-08-04T10:00:00Z", null, plan, List.of(), WORKSPACE_PATH);

        assertTrue(manifest.units().isEmpty());
        assertEquals(List.of(manual), manifest.manualAnalysisRequired());
    }

    @Test
    @DisplayName("units preserve severity order: critical, then high, then medium, then low")
    void unitsPreserveSeverityOrder() {
        RemediationPlan plan = planWith(
                List.of(library("c", "CRITICAL")), List.of(library("h", "HIGH")),
                List.of(library("m", "MEDIUM")), List.of(library("l", "LOW")), List.of());

        RunManifest manifest = RunManifestBuilder.build(
                RUNS_ROOT, "run1", "2026-08-04T10:00:00Z", "sha123", plan,
                List.of(branch("critical"), branch("high"), branch("medium"), branch("low")), WORKSPACE_PATH);

        List<String> order = manifest.units().stream().map(RemediationUnit::artifactId).toList();
        assertEquals(List.of("c", "h", "m", "l"), order);
    }

    @Test
    @DisplayName("manifest carries the run id, generatedAt and base commit through unchanged")
    void manifestCarriesTopLevelFieldsThrough() {
        RemediationPlan plan = planWith(List.of(), List.of(), List.of(), List.of(), List.of());

        RunManifest manifest = RunManifestBuilder.build(
                RUNS_ROOT, "run1", "2026-08-04T10:00:00Z", "sha123", plan, List.of(), WORKSPACE_PATH);

        assertEquals("run1", manifest.runId());
        assertEquals("2026-08-04T10:00:00Z", manifest.generatedAt());
        assertEquals("sha123", manifest.baseCommitSha());
        assertEquals(RunManifest.CURRENT_VERSION, manifest.manifestVersion());
    }
}
