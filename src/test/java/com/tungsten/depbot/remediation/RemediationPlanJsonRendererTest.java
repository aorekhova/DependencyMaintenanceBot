package com.tungsten.depbot.remediation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemediationPlanJsonRendererTest {

    private static final JsonMapper STRICT_READER = JsonMapper.builder().build();

    private final RemediationPlanJsonRenderer renderer = new RemediationPlanJsonRenderer();

    private static RemediationPlan samplePlan() {
        LibraryRemediation critical = new LibraryRemediation(
                "org.bouncycastle", "bcprov-jdk18on", "1.84", "1.85", "CRITICAL",
                List.of("CVE-2026-1", "CVE-2026-2"), null);
        LibraryRemediation manual = new LibraryRemediation(
                "com.example", "widget", "1.0", TargetVersionResolver.MANUAL_ANALYSIS_REQUIRED, "OTHER",
                List.of("CVE-2026-3"), null);

        return new RemediationPlan(
                "2026-08-04T10:00:00Z", "2026-08-04T09:00:00Z", RemediationPlan.CURRENT_VERSION,
                List.of(critical), List.of(), List.of(), List.of(), List.of(manual));
    }

    @Test
    @DisplayName("round-trips through plain Jackson record binding")
    void roundTrips() throws Exception {
        RemediationPlan original = samplePlan();
        RemediationPlan parsed = STRICT_READER.readValue(renderer.render(original), RemediationPlan.class);

        assertEquals(original, parsed);
    }

    @Test
    @DisplayName("output always uses LF line endings, never CRLF")
    void usesLfOnly() {
        String json = renderer.render(samplePlan());

        assertFalse(json.contains("\r\n"), "output must not contain CRLF");
        assertTrue(json.contains("\n"), "output must contain LF");
    }

    @Test
    @DisplayName("the five severity buckets are all present as top-level fields")
    void allFiveBucketsArePresent() throws Exception {
        JsonNode root = STRICT_READER.readTree(renderer.render(samplePlan()));

        assertTrue(root.has("critical"));
        assertTrue(root.has("high"));
        assertTrue(root.has("medium"));
        assertTrue(root.has("low"));
        assertTrue(root.has("manualAnalysisRequired"));
        assertTrue(root.has("generatedAt"));
        assertTrue(root.has("sourceReportGeneratedAt"));
        assertTrue(root.has("reportVersion"));
    }

    @Test
    @DisplayName("a MANUAL_ANALYSIS_REQUIRED target version is rendered literally")
    void manualAnalysisRequiredIsRenderedLiterally() {
        String json = renderer.render(samplePlan());
        assertTrue(json.contains("MANUAL_ANALYSIS_REQUIRED"));
    }

    @Test
    @DisplayName("a non-null manualAnalysisReason is rendered as its own JSON field")
    void manualAnalysisReasonIsRendered() throws Exception {
        LibraryRemediation blocked = new LibraryRemediation(
                "com.fasterxml.jackson.core", "jackson-databind", "2.22.0",
                TargetVersionResolver.MANUAL_ANALYSIS_REQUIRED, "MEDIUM", List.of("CVE-1"),
                "no forward fix candidate above 2.22.0");
        RemediationPlan plan = new RemediationPlan("2026-08-04T10:00:00Z", "2026-08-04T09:00:00Z",
                RemediationPlan.CURRENT_VERSION, List.of(), List.of(), List.of(), List.of(), List.of(blocked));

        String json = renderer.render(plan);
        assertTrue(json.contains("\"manualAnalysisReason\" : \"no forward fix candidate above 2.22.0\""), json);

        JsonNode root = STRICT_READER.readTree(json);
        assertTrue(root.get("manualAnalysisRequired").get(0).has("manualAnalysisReason"));
    }

    @Test
    @DisplayName("manualAnalysisReason is null in JSON when no reason was recorded")
    void manualAnalysisReasonIsNullWhenAbsent() throws Exception {
        JsonNode root = STRICT_READER.readTree(renderer.render(samplePlan()));

        assertTrue(root.get("critical").get(0).get("manualAnalysisReason").isNull());
    }
}
