package com.tungsten.depbot.report.actionable;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.Fixtures;
import com.tungsten.depbot.mend.MendResponseParser;
import com.tungsten.depbot.mend.model.VulnerabilityRecord;
import com.tungsten.depbot.report.SecretRedactor;
import com.tungsten.depbot.report.SeverityCounts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonReportRendererTest {

    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-01-02T03:04:05Z"), ZoneOffset.UTC);

    private final JsonReportRenderer renderer = new JsonReportRenderer();

    /** Strict reader: unknown properties fail, so an accidentally added field is caught. */
    private static final ObjectMapper STRICT_READER = JsonMapper.builder().build();

    // ---------- helpers ----------

    private static ActionableReport reportFrom(String fixture) {
        List<VulnerabilityRecord> vulnerabilities = new MendResponseParser()
                .parse(Fixtures.load(fixture)).vulnerabilities();
        return new ActionableReportFactory(FIXED_CLOCK)
                .build(vulnerabilities, SeverityCounts.from(vulnerabilities));
    }

    private static ActionableReport emptyReport() {
        return ActionableReport.of("2026-01-02T03:04:05Z",
                new ActionableSummary(0, 0, 0, 0, 0, 0, 0), List.of());
    }

    private JsonNode parse(String json) {
        return assertDoesNotThrow(() -> STRICT_READER.readTree(json),
                "renderer produced text that is not valid JSON");
    }

    private static Set<String> fieldNames(JsonNode node) {
        Set<String> names = new LinkedHashSet<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }

    // ---------- validity and round trip ----------

    @Test
    @DisplayName("the rendered text is valid JSON")
    void outputIsValidJson() {
        assertTrue(parse(renderer.render(reportFrom("actionable-full-detail.json"))).isObject());
    }

    @Test
    @DisplayName("the report round-trips back to an equal object")
    void reportRoundTrips() {
        ActionableReport original = reportFrom("actionable-full-detail.json");

        ActionableReport parsed = assertDoesNotThrow(() -> STRICT_READER
                .readValue(renderer.render(original), ActionableReport.class));

        assertEquals(original, parsed);
    }

    @Test
    @DisplayName("a report with every awkward shape still round-trips")
    void awkwardReportRoundTrips() {
        ActionableReport original = reportFrom("actionable-null-fix-elements.json");

        assertEquals(original, assertDoesNotThrow(() -> STRICT_READER
                .readValue(renderer.render(original), ActionableReport.class)));
    }

    // ---------- line endings ----------

    @ParameterizedTest
    @ValueSource(strings = {
            "actionable-full-detail.json",
            "actionable-multiple-fixes.json",
            "actionable-hostile-text.json",
            "actionable-missing-coordinates.json"
    })
    @DisplayName("the output contains no carriage return, whatever the platform")
    void outputContainsNoCarriageReturn(String fixture) {
        String json = renderer.render(reportFrom(fixture));

        assertFalse(json.contains("\r"),
                "CRLF would make the same report differ between Windows and a Linux build agent");
    }

    @Test
    @DisplayName("an empty report also renders with LF only")
    void emptyReportHasNoCarriageReturn() {
        assertFalse(renderer.render(emptyReport()).contains("\r"));
    }

    @Test
    @DisplayName("the output ends with a single newline")
    void outputEndsWithNewline() {
        String json = renderer.render(emptyReport());

        assertTrue(json.endsWith("\n"));
        assertFalse(json.endsWith("\n\n"));
    }

    // ---------- formatting ----------

    @Test
    @DisplayName("the output is pretty printed with two-space indentation")
    void outputIsPrettyPrinted() {
        String json = renderer.render(reportFrom("actionable-full-detail.json"));

        assertTrue(json.lines().count() > 20, "expected a multi-line document");
        assertTrue(json.lines().anyMatch(line -> line.startsWith("  \"generatedAt\"")),
                "top-level fields should be indented by two spaces");
        assertTrue(json.lines().anyMatch(line -> line.startsWith("      \"vulnerabilityId\"")
                        || line.startsWith("      \"type\"")),
                "nested findings should be indented further");
    }

    @Test
    @DisplayName("rendering the same report twice is byte-identical")
    void renderingIsDeterministic() {
        ActionableReport report = reportFrom("actionable-full-detail.json");

        assertEquals(renderer.render(report), renderer.render(report));
        assertEquals(new JsonReportRenderer().render(report), renderer.render(report),
                "a fresh renderer instance must produce the same bytes");
    }

    // ---------- schema contract ----------

    @Test
    @DisplayName("the root carries exactly the five documented fields, in declaration order")
    void rootSchemaIsPinned() {
        JsonNode root = parse(renderer.render(emptyReport()));

        assertEquals(List.of("generatedAt", "reportVersion", "summary", "findings",
                        "sourceSnapshotFingerprint"),
                new ArrayList<>(fieldNames(root)),
                "the published JSON contract changed; downstream consumers depend on this shape");
    }

    @Test
    @DisplayName("the summary carries exactly the seven documented counts")
    void summarySchemaIsPinned() {
        JsonNode summary = parse(renderer.render(emptyReport())).get("summary");

        assertEquals(List.of("totalVulnerabilities", "criticalCount", "highCount", "mediumCount",
                        "lowCount", "otherCount", "actionableCount"),
                new ArrayList<>(fieldNames(summary)));
    }

    @Test
    @DisplayName("a finding carries exactly the seventeen documented fields")
    void findingSchemaIsPinned() {
        JsonNode finding = parse(renderer.render(reportFrom("actionable-full-detail.json")))
                .get("findings").get(0);

        assertEquals(List.of("vulnerabilityId", "type", "severity", "cvss3Severity", "cvss3Score",
                        "cvss3ScoreNumeric", "score", "scoreMetadataVector", "description",
                        "publishedDate", "lastUpdatedDate", "referenceUrl", "product", "project",
                        "library", "locations", "remediation"),
                new ArrayList<>(fieldNames(finding)));
    }

    @Test
    @DisplayName("derived helper methods are not serialised as fields")
    void derivedAccessorsAreNotSerialised() {
        JsonNode root = parse(renderer.render(reportFrom("actionable-full-detail.json")));

        // hasActionableFindings(), sumOfBuckets(), hasTopFix() and hasAnyFix() are conveniences,
        // not part of the contract. If Jackson ever started emitting them, consumers could begin
        // relying on fields we never intended to publish.
        assertFalse(root.has("hasActionableFindings"));
        assertFalse(root.get("summary").has("sumOfBuckets"));

        JsonNode remediation = root.get("findings").get(0).get("remediation");
        assertEquals(List.of("topFix", "allFixes"), new ArrayList<>(fieldNames(remediation)));
    }

    @Test
    @DisplayName("library and location keep their documented shapes")
    void nestedSchemasArePinned() {
        JsonNode finding = parse(renderer.render(reportFrom("actionable-full-detail.json")))
                .get("findings").get(0);

        assertEquals(List.of("groupId", "artifactId", "version", "coordinates", "name", "filename",
                        "type", "sha1", "keyUuid", "architecture", "languageVersion", "description"),
                new ArrayList<>(fieldNames(finding.get("library"))));

        assertEquals(List.of("path", "matchType"),
                new ArrayList<>(fieldNames(finding.get("locations").get(0))));
    }

    // ---------- null and empty representation ----------

    @Test
    @DisplayName("absent values are written as explicit null, not omitted")
    void absentValuesAreExplicitNull() {
        JsonNode finding = parse(renderer.render(reportFrom("actionable-minimal-fields.json")))
                .get("findings").get(0);

        assertTrue(finding.has("library"), "the key should be present even when there is no value");
        assertTrue(finding.get("library").isNull());
        assertTrue(finding.get("cvss3ScoreNumeric").isNull());
        assertTrue(finding.get("description").isNull());
        assertTrue(finding.get("remediation").get("topFix").isNull());
    }

    @Test
    @DisplayName("empty collections render as [] rather than null")
    void emptyCollectionsRenderAsArrays() {
        JsonNode root = parse(renderer.render(emptyReport()));
        assertTrue(root.get("findings").isArray());
        assertEquals(0, root.get("findings").size());

        JsonNode finding = parse(renderer.render(reportFrom("actionable-minimal-fields.json")))
                .get("findings").get(0);
        assertTrue(finding.get("locations").isArray());
        assertTrue(finding.get("remediation").get("allFixes").isArray());
    }

    @Test
    @DisplayName("the numeric score is emitted as a JSON number, the raw one as a string")
    void scoreRepresentations() {
        JsonNode finding = parse(renderer.render(reportFrom("actionable-full-detail.json")))
                .get("findings").get(0);

        assertTrue(finding.get("cvss3ScoreNumeric").isNumber());
        assertEquals(8.1, finding.get("cvss3ScoreNumeric").asDouble());
        assertTrue(finding.get("cvss3Score").isTextual());
        assertEquals("8.1", finding.get("cvss3Score").asText());
    }

    @Test
    @DisplayName("a non-finite raw score keeps its text while the numeric field stays null")
    void nonFiniteScoreRendersSafely() {
        JsonNode findings = parse(renderer.render(reportFrom("actionable-non-finite-scores.json")))
                .get("findings");

        // NaN as a bare JSON literal would be invalid JSON; it must only appear as a string.
        boolean sawNaNAsText = false;
        for (JsonNode finding : findings) {
            if ("NaN".equals(finding.get("cvss3Score").asText())) {
                sawNaNAsText = true;
                assertTrue(finding.get("cvss3ScoreNumeric").isNull());
            }
        }
        assertTrue(sawNaNAsText, "expected the NaN entry to survive as text");
    }

    // ---------- escaping ----------

    @Test
    @DisplayName("quotes, backslashes and newlines are escaped and survive a round trip exactly")
    void hostileTextIsEscapedAndPreserved() {
        ActionableReport original = reportFrom("actionable-hostile-text.json");
        String json = renderer.render(original);

        // A raw newline inside a string literal would be invalid JSON.
        JsonNode parsed = parse(json);
        String description = parsed.get("findings").get(0).get("description").asText();

        assertTrue(description.contains("\n"), "the newline should survive as data");
        assertTrue(description.contains("\""), "the quote should survive as data");
        assertTrue(description.contains("\\"), "the backslash should survive as data");
        assertEquals(original.findings().get(0).description(), description);
    }

    // ---------- redaction, deferred from checkpoint 6 ----------

    @Test
    @DisplayName("secrets masked in the model do not appear in the rendered JSON")
    void redactedSecretsAbsentFromJson() {
        String userKey = "USERKEY-DO-NOT-LEAK-9f3a";
        String token = "TOKEN-DO-NOT-LEAK-7b1c";

        ActionableReport redacted = ActionableReportRedactor
                .withSecrets(userKey, token)
                .redact(reportFrom("actionable-hostile-text.json"));

        String json = renderer.render(redacted);

        assertFalse(json.contains(userKey), "user key reached the JSON report");
        assertFalse(json.contains(token), "project token reached the JSON report");
        assertTrue(json.contains(SecretRedactor.MASK));
        assertTrue(parse(json).isObject(), "the JSON must remain valid after redaction");
    }

    @ParameterizedTest
    @ValueSource(strings = {"SEC-quote\"inside-a1", "SEC-back\\slash-b2", "SEC-new\nline-c3"})
    @DisplayName("an awkwardly shaped secret cannot survive into the JSON via escaping")
    void awkwardSecretsCannotSurviveEscaping(String secret) {
        // This is the case a text-level replace would miss: after escaping, the secret's bytes in
        // the file differ from the bytes being searched for. Model-level redaction avoids that.
        ActionableFinding finding = new ActionableFinding("FAKE-CVE-0000-0001", null, "HIGH", null,
                null, null, null, null, "leaks " + secret + " here", null, null, null, null, null,
                null, List.of(new FindingLocation("/synthetic/" + secret, "EXACT_MATCH")), null);

        ActionableReport redacted = ActionableReportRedactor.withSecrets(secret)
                .redact(ActionableReport.of("2026-01-02T03:04:05Z",
                        new ActionableSummary(1, 0, 1, 0, 0, 0, 1), List.of(finding)));

        String json = renderer.render(redacted);

        assertFalse(json.contains(secret), "the raw secret appeared in the JSON");
        assertTrue(parse(json).isObject());
        assertFalse(parse(json).get("findings").get(0).get("description").asText()
                .contains(secret), "the secret survived once unescaped again");
    }

    // ---------- contract ----------

    @Test
    @DisplayName("a null report is rejected")
    void nullReportRejected() {
        assertThrows(NullPointerException.class, () -> renderer.render(null));
    }
}
