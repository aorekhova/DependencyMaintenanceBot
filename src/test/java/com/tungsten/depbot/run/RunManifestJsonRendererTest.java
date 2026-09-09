package com.tungsten.depbot.run;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.remediation.LibraryRemediation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RunManifestJsonRendererTest {

    private static final JsonMapper STRICT_READER = JsonMapper.builder().build();

    private final RunManifestJsonRenderer renderer = new RunManifestJsonRenderer();

    private static RunManifest sampleManifest() {
        RemediationUnit unit = new RemediationUnit(
                "run1", "critical__org.bouncycastle__bcprov-jdk18on", "CRITICAL",
                "org.bouncycastle", "bcprov-jdk18on", "1.84", "1.85",
                List.of("CVE-2026-1"), "remediation/run1/critical", "/repo-remediation-run1-critical",
                "reports/runs/run1/tasks/critical/org.bouncycastle__bcprov-jdk18on.md",
                RemediationUnit.PENDING_STATUS, 0);
        LibraryRemediation manual = new LibraryRemediation("com.example", "widget", "1.0",
                "MANUAL_ANALYSIS_REQUIRED", "OTHER", List.of("CVE-2026-2"), null);

        return new RunManifest("run1", "2026-08-04T10:00:00Z", RunManifest.CURRENT_VERSION, "sha123",
                "opus", List.of(unit), List.of(manual));
    }

    @Test
    @DisplayName("round-trips through plain Jackson record binding")
    void roundTrips() throws Exception {
        RunManifest original = sampleManifest();
        RunManifest parsed = STRICT_READER.readValue(renderer.render(original), RunManifest.class);

        assertEquals(original, parsed);
    }

    @Test
    @DisplayName("output always uses LF line endings, never CRLF")
    void usesLfOnly() {
        String json = renderer.render(sampleManifest());

        assertFalse(json.contains("\r\n"));
        assertTrue(json.contains("\n"));
    }

    @Test
    @DisplayName("every documented field is present as a top-level or unit-level JSON field")
    void allDocumentedFieldsArePresent() throws Exception {
        JsonNode root = STRICT_READER.readTree(renderer.render(sampleManifest()));

        assertTrue(root.has("runId"));
        assertTrue(root.has("generatedAt"));
        assertTrue(root.has("manifestVersion"));
        assertTrue(root.has("baseCommitSha"));
        assertTrue(root.has("model"));
        assertTrue(root.has("units"));
        assertTrue(root.has("manualAnalysisRequired"));

        JsonNode unit = root.get("units").get(0);
        assertTrue(unit.has("runId"));
        assertTrue(unit.has("unitId"));
        assertTrue(unit.has("severity"));
        assertTrue(unit.has("groupId"));
        assertTrue(unit.has("artifactId"));
        assertTrue(unit.has("currentVersion"));
        assertTrue(unit.has("targetVersion"));
        assertTrue(unit.has("vulnerabilityIds"));
        assertTrue(unit.has("branch"));
        assertTrue(unit.has("workspacePath"));
        assertTrue(unit.has("taskFile"));
        assertTrue(unit.has("status"));
        assertTrue(unit.has("attempts"));
    }
}
