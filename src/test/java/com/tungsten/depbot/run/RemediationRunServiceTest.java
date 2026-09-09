package com.tungsten.depbot.run;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.git.CreatedBranch;
import com.tungsten.depbot.git.RemediationBranchOutcome;
import com.tungsten.depbot.remediation.LibraryRemediation;
import com.tungsten.depbot.remediation.RemediationPlan;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemediationRunServiceTest {

    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-08-04T10:00:00Z"), ZoneOffset.UTC);
    private static final String WORKSPACE_PATH = "/repo";

    @TempDir
    Path tempDir;

    private RemediationRunService service() {
        return new RemediationRunService(FIXED_CLOCK, tempDir);
    }

    private static LibraryRemediation library(String artifactId) {
        return new LibraryRemediation("g", artifactId, "1.0", "2.0", "CRITICAL", List.of("CVE-1"), null);
    }

    private static RemediationPlan planWithOneCritical() {
        return new RemediationPlan("2026-08-04T09:00:00Z", "2026-08-04T09:00:00Z",
                RemediationPlan.CURRENT_VERSION, List.of(library("a")), List.of(), List.of(), List.of(), List.of());
    }

    private static RemediationBranchOutcome outcomeWithOneCritical(String runId) {
        CreatedBranch branch = new CreatedBranch("critical", "remediation/" + runId + "/critical");
        return new RemediationBranchOutcome(planWithOneCritical(), runId, "sha123", List.of(branch), List.of(), List.of());
    }

    @Test
    @DisplayName("recordRun writes the manifest and one task file per unit")
    void recordRunWritesManifestAndTaskFiles() {
        RunManifest manifest = service().recordRun(outcomeWithOneCritical("run1"), WORKSPACE_PATH);

        Path manifestPath = tempDir.resolve("run1").resolve("run-manifest.json");
        assertTrue(Files.exists(manifestPath));
        assertEquals(1, manifest.units().size());

        Path taskPath = Path.of(manifest.units().get(0).taskFile());
        assertTrue(Files.exists(taskPath));
        assertTrue(taskPath.startsWith(tempDir.resolve("run1").resolve("tasks").resolve("critical")));
    }

    @Test
    @DisplayName("the written manifest file round-trips to the same manifest recordRun returned")
    void writtenManifestMatchesReturnedManifest() throws Exception {
        RunManifest manifest = service().recordRun(outcomeWithOneCritical("run1"), WORKSPACE_PATH);

        String written = Files.readString(tempDir.resolve("run1").resolve("run-manifest.json"), StandardCharsets.UTF_8);
        RunManifest parsed = new JsonMapper().readValue(written, RunManifest.class);

        assertEquals(manifest, parsed);
    }

    @Test
    @DisplayName("manifestPathFor reports the path without writing anything")
    void manifestPathForDoesNotWrite() {
        Path path = service().manifestPathFor("run1");

        assertEquals(tempDir.resolve("run1").resolve("run-manifest.json"), path);
        assertTrue(Files.notExists(path));
    }

    @Test
    @DisplayName("an empty outcome (no units, no manualAnalysisRequired) still writes an empty manifest")
    void emptyOutcomeStillWritesAnEmptyManifest() {
        RemediationPlan emptyPlan = new RemediationPlan("2026-08-04T09:00:00Z", "2026-08-04T09:00:00Z",
                RemediationPlan.CURRENT_VERSION, List.of(), List.of(), List.of(), List.of(), List.of());
        RemediationBranchOutcome outcome = new RemediationBranchOutcome(
                emptyPlan, "run1", null, List.of(), List.of("critical", "high", "medium", "low"), List.of());

        RunManifest manifest = service().recordRun(outcome, WORKSPACE_PATH);

        assertTrue(manifest.units().isEmpty());
        assertTrue(manifest.manualAnalysisRequired().isEmpty());
        assertTrue(Files.exists(tempDir.resolve("run1").resolve("run-manifest.json")));
    }

    @Test
    @DisplayName("a null run id in the outcome is rejected rather than writing to an unnamed directory")
    void nullRunIdIsRejected() {
        RemediationBranchOutcome outcome = new RemediationBranchOutcome(
                planWithOneCritical(), null, null, List.of(), List.of(), List.of());

        assertThrows(NullPointerException.class, () -> service().recordRun(outcome, WORKSPACE_PATH));
    }

    @Test
    @DisplayName("a null workspace path is rejected")
    void nullWorkspacePathIsRejected() {
        assertThrows(NullPointerException.class, () -> service().recordRun(outcomeWithOneCritical("run1"), null));
    }

    @Test
    @DisplayName("a runs root blocked by an existing file throws RunManifestWriteException, not a raw IOException")
    void blockedRunsRootThrowsRunManifestWriteException() throws Exception {
        Path blockingFile = tempDir.resolve("blocked");
        Files.writeString(blockingFile, "not a directory", StandardCharsets.UTF_8);
        RemediationRunService blockedService = new RemediationRunService(FIXED_CLOCK, blockingFile);

        assertThrows(RunManifestWriteException.class,
                () -> blockedService.recordRun(outcomeWithOneCritical("run1"), WORKSPACE_PATH));
    }

    @Test
    @DisplayName("two different runs never collide, each getting its own directory")
    void twoRunsDoNotCollide() {
        service().recordRun(outcomeWithOneCritical("run1"), WORKSPACE_PATH);
        service().recordRun(outcomeWithOneCritical("run2"), WORKSPACE_PATH);

        assertTrue(Files.exists(tempDir.resolve("run1").resolve("run-manifest.json")));
        assertTrue(Files.exists(tempDir.resolve("run2").resolve("run-manifest.json")));
    }
}
