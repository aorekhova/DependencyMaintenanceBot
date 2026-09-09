package com.tungsten.depbot.report.actionable;

import com.tungsten.depbot.Fixtures;
import com.tungsten.depbot.mend.MendResponseParser;
import com.tungsten.depbot.mend.model.VulnerabilityRecord;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ActionableReportMapperTest {

    private final MendResponseParser parser = new MendResponseParser();

    private List<VulnerabilityRecord> parse(String fixture) {
        return parser.parse(Fixtures.load(fixture)).vulnerabilities();
    }

    private List<ActionableFinding> map(String fixture) {
        return ActionableReportMapper.toFindings(parse(fixture));
    }

    private ActionableFinding mapFirst(String fixture) {
        return map(fixture).get(0);
    }

    // ---------- full mapping ----------

    @Test
    @DisplayName("every field maps across from a fully populated Mend record")
    void fullRecordMaps() {
        ActionableFinding f = mapFirst("actionable-full-detail.json");

        assertEquals("FAKE-CVE-0000-0101", f.vulnerabilityId());
        assertEquals("SECURITY_VULNERABILITY", f.type());
        assertEquals("HIGH", f.severity());
        assertEquals("high", f.cvss3Severity());
        assertEquals("8.1", f.cvss3Score());
        assertEquals(8.1, f.cvss3ScoreNumeric());
        assertEquals("8.1", f.score());
        assertEquals("FAKE/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", f.scoreMetadataVector());
        assertTrue(f.description().startsWith("Synthetic finding"));
        assertEquals("2020-01-15", f.publishedDate());
        assertEquals("2020-06-30", f.lastUpdatedDate());
        assertEquals("https://example.invalid/fake-advisory/0101", f.referenceUrl());
        assertEquals("synthetic-test-product", f.product());
        assertEquals("synthetic-test-project", f.project());
    }

    @Test
    @DisplayName("severity is normalised to the canonical uppercase name")
    void severityIsNormalised() {
        assertEquals("HIGH", mapFirst("actionable-full-detail.json").severity());
        assertEquals("CRITICAL", mapFirst("actionable-minimal-fields.json").severity());
    }

    @Test
    @DisplayName("mapping does not filter by severity; selection is a separate concern")
    void mappingDoesNotFilter() {
        VulnerabilityRecord medium = new VulnerabilityRecord("medium");

        assertEquals("MEDIUM", ActionableReportMapper.toFinding(medium).severity());
    }

    // ---------- library and coordinates ----------

    @Test
    @DisplayName("a complete library yields full coordinates")
    void completeCoordinates() {
        AffectedLibrary library = mapFirst("actionable-full-detail.json").library();

        assertNotNull(library);
        assertEquals("com.example.fake:example-fake-lib-core:1.0.0", library.coordinates());
        assertEquals("com.example.fake", library.groupId());
        assertEquals("example-fake-lib-core", library.artifactId());
        assertEquals("1.0.0", library.version());
        assertEquals("example-fake-lib-core-1.0.0.jar", library.name());
        assertEquals("example-fake-lib-core-1.0.0.jar", library.filename());
        assertEquals("JAVA_ARCHIVE", library.type());
        assertEquals("0000000000000000000000000000000000000101", library.sha1());
        assertEquals("00000000-0000-0000-0000-000000000101", library.keyUuid());
    }

    @ParameterizedTest
    @CsvSource({
            "0, FAKE-CVE-0000-0501, missing groupId",
            "1, FAKE-CVE-0000-0502, missing artifactId",
            "2, FAKE-CVE-0000-0503, missing version",
            "3, FAKE-CVE-0000-0504, blank groupId"
    })
    @DisplayName("coordinates stay null unless all three parts are present and non-blank")
    void incompleteCoordinatesAreNull(int index, String expectedId, String reason) {
        List<ActionableFinding> findings = map("actionable-missing-coordinates.json");
        ActionableFinding f = findings.get(index);

        assertEquals(expectedId, f.vulnerabilityId());
        assertNotNull(f.library(), "the library itself must still be reported");
        assertNull(f.library().coordinates(), "coordinates must not be fabricated when " + reason);
    }

    @Test
    @DisplayName("the remaining library fields survive even when coordinates cannot be built")
    void partialLibraryFieldsRetained() {
        ActionableFinding f = map("actionable-missing-coordinates.json").get(0);

        assertNull(f.library().coordinates());
        assertNull(f.library().groupId());
        assertEquals("example-fake-nogroup", f.library().artifactId());
        assertEquals("1.0.0", f.library().version());
        assertEquals("example-fake-nogroup-1.0.0.jar", f.library().name());
    }

    @Test
    @DisplayName("the one complete library in that fixture does get coordinates")
    void completeLibraryAmongIncompleteOnes() {
        ActionableFinding f = map("actionable-missing-coordinates.json").get(4);

        assertEquals("com.example.fake:example-fake-complete:4.0.0", f.library().coordinates());
    }

    @Test
    @DisplayName("an absent library leaves library null but still produces the finding")
    void absentLibraryStillProducesFinding() {
        List<ActionableFinding> findings = map("actionable-no-library.json");

        assertEquals(1, findings.size(), "a missing library must never drop the finding");
        assertNull(findings.get(0).library());
        assertEquals("FAKE-CVE-0000-0601", findings.get(0).vulnerabilityId());
        assertEquals(9.4, findings.get(0).cvss3ScoreNumeric());
    }

    @Test
    @DisplayName("an explicitly null library leaves library null")
    void nullLibraryStillProducesFinding() {
        ActionableFinding f = mapFirst("actionable-null-nested.json");

        assertNull(f.library());
        assertEquals("FAKE-CVE-0000-0301", f.vulnerabilityId());
    }

    @Test
    @DisplayName("coordinate parts are stripped rather than concatenated raw")
    void coordinatePartsAreStripped() {
        ActionableFinding f = map("actionable-missing-coordinates.json").get(4);

        assertFalse(f.library().coordinates().contains(" "),
                "coordinates should not carry stray whitespace: " + f.library().coordinates());
    }

    // ---------- locations ----------

    @Test
    @DisplayName("multiple locations are preserved in order, with path and matchType not swapped")
    void multipleLocationsPreserved() {
        List<FindingLocation> locations = mapFirst("actionable-full-detail.json").locations();

        assertEquals(2, locations.size());
        assertEquals("/synthetic/build/libs/example-fake-lib-core-1.0.0.jar",
                locations.get(0).path());
        assertEquals("EXACT_MATCH", locations.get(0).matchType());
        assertEquals("/synthetic/cache/example-fake-lib-core-1.0.0.jar", locations.get(1).path());
        assertEquals("FILENAME_MATCH", locations.get(1).matchType());
    }

    @Test
    @DisplayName("a single location maps correctly")
    void singleLocation() {
        List<FindingLocation> locations = mapFirst("actionable-no-library.json").locations();

        assertEquals(1, locations.size());
        assertEquals("/synthetic/lib/unknown-origin.jar", locations.get(0).path());
    }

    @Test
    @DisplayName("an absent locations key yields an empty list, never null")
    void absentLocationsYieldEmptyList() {
        ActionableFinding f = map("actionable-no-locations.json").get(0);

        assertNotNull(f.locations());
        assertTrue(f.locations().isEmpty());
    }

    @Test
    @DisplayName("an empty locations array yields an empty list")
    void emptyLocationsArrayYieldsEmptyList() {
        assertTrue(map("actionable-no-locations.json").get(1).locations().isEmpty());
    }

    @Test
    @DisplayName("an explicitly null locations value yields an empty list")
    void nullLocationsYieldEmptyList() {
        assertTrue(mapFirst("actionable-null-nested.json").locations().isEmpty());
    }

    @Test
    @DisplayName("null elements inside locations are skipped, the rest keep their order")
    void nullLocationElementsSkipped() {
        List<FindingLocation> locations = mapFirst("actionable-null-fix-elements.json").locations();

        assertEquals(2, locations.size());
        assertEquals("/synthetic/first.jar", locations.get(0).path());
        assertEquals("/synthetic/second.jar", locations.get(1).path());
    }

    // ---------- remediation ----------

    @Test
    @DisplayName("topFix maps in full when present")
    void topFixMaps() {
        RecommendedFix topFix = mapFirst("actionable-multiple-fixes.json").remediation().topFix();

        assertNotNull(topFix);
        assertEquals("FAKE-CVE-0000-0801", topFix.vulnerability());
        assertEquals("UPGRADE_VERSION", topFix.type());
        assertEquals("EXAMPLE_FAKE_ADVISORY", topFix.origin());
        assertEquals("https://example.invalid/fake-fix/0801-top", topFix.url());
        assertEquals("com.example.fake:example-fake-multi:2.0.0", topFix.fixResolution());
        assertEquals("2021-03-04", topFix.date());
        assertEquals("Preferred synthetic remediation.", topFix.message());
    }

    @Test
    @DisplayName("every entry in allFixes is preserved in order")
    void allFixesPreserved() {
        Remediation remediation = mapFirst("actionable-multiple-fixes.json").remediation();

        assertEquals(3, remediation.allFixes().size());
        assertEquals("UPGRADE_VERSION", remediation.allFixes().get(0).type());
        assertEquals("CHANGE_FILES", remediation.allFixes().get(1).type());
        assertEquals("WORKAROUND", remediation.allFixes().get(2).type());
    }

    @Test
    @DisplayName("a fix carrying only a type is retained rather than discarded")
    void sparseFixRetained() {
        RecommendedFix sparse =
                mapFirst("actionable-multiple-fixes.json").remediation().allFixes().get(2);

        assertEquals("WORKAROUND", sparse.type());
        assertNull(sparse.fixResolution());
        assertNull(sparse.origin());
        assertNull(sparse.url());
        assertNull(sparse.date());
        assertNull(sparse.message());
    }

    @Test
    @DisplayName("an absent topFix still leaves allFixes mapped")
    void absentTopFixKeepsAllFixes() {
        Remediation remediation = map("actionable-multiple-fixes.json").get(1).remediation();

        assertNull(remediation.topFix());
        assertEquals(1, remediation.allFixes().size());
        assertEquals("com.example.fake:example-fake-notop:1.0.1",
                remediation.allFixes().get(0).fixResolution());
        assertTrue(remediation.hasAnyFix());
    }

    @Test
    @DisplayName("no remediation at all yields the empty remediation, not null")
    void noRemediationYieldsEmpty() {
        Remediation remediation = map("actionable-multiple-fixes.json").get(2).remediation();

        assertNotNull(remediation);
        assertNull(remediation.topFix());
        assertTrue(remediation.allFixes().isEmpty());
        assertFalse(remediation.hasAnyFix());
    }

    @Test
    @DisplayName("null elements inside allFixes are skipped, the rest keep their order")
    void nullFixElementsSkipped() {
        Remediation remediation = mapFirst("actionable-null-fix-elements.json").remediation();

        assertEquals(2, remediation.allFixes().size());
        assertEquals("com.example.fake:example-fake-nulls:1.0.1",
                remediation.allFixes().get(0).fixResolution());
        assertEquals("Apply the second synthetic patch.",
                remediation.allFixes().get(1).fixResolution());
    }

    @Test
    @DisplayName("a list of only null fixes does not throw and yields no fixes")
    void onlyNullFixesIsSafe() {
        List<com.tungsten.depbot.mend.model.MendFix> onlyNulls =
                new ArrayList<>(Arrays.asList(null, null));
        VulnerabilityRecord record = new VulnerabilityRecord(null, null, "high", null, null, null,
                null, null, null, null, null, null, null, null, null, onlyNulls, null);

        Remediation remediation =
                assertDoesNotThrow(() -> ActionableReportMapper.toFinding(record).remediation());

        assertTrue(remediation.allFixes().isEmpty());
    }

    // ---------- score parsing ----------

    @ParameterizedTest
    @CsvSource({"9.8, 9.8", "7.5, 7.5", "0, 0.0", "10, 10.0", "  4.2  , 4.2"})
    @DisplayName("a valid score parses to a number")
    void validScoresParse(String raw, double expected) {
        assertEquals(expected, ActionableReportMapper.parseScore(raw));
    }

    @ParameterizedTest
    @ValueSource(strings = {"NaN", "Infinity", "-Infinity"})
    @DisplayName("non-finite scores become null rather than a poisoned number")
    void nonFiniteScoresBecomeNull(String raw) {
        // parseDouble accepts all three without throwing, so the finite check is what rejects them.
        assertNull(ActionableReportMapper.parseScore(raw),
                raw + " must not survive as a numeric score");
    }

    @ParameterizedTest
    @ValueSource(strings = {"N/A", "", "   ", "high", "8,1", "8.1.2", "--3"})
    @DisplayName("unparseable and blank scores become null")
    void unparseableScoresBecomeNull(String raw) {
        assertNull(ActionableReportMapper.parseScore(raw));
    }

    @Test
    @DisplayName("an absent score becomes null")
    void absentScoreBecomesNull() {
        assertNull(ActionableReportMapper.parseScore(null));
        assertNull(mapFirst("actionable-minimal-fields.json").cvss3ScoreNumeric());
    }

    @Test
    @DisplayName("the raw score string is preserved alongside the parsed number")
    void rawScorePreservedAlongsideNumeric() {
        List<ActionableFinding> findings = map("actionable-non-finite-scores.json");

        // Faithful raw value, null numeric: nothing fabricated, nothing silently altered.
        assertEquals("NaN", findings.get(0).cvss3Score());
        assertNull(findings.get(0).cvss3ScoreNumeric());

        assertEquals("N/A", findings.get(3).cvss3Score());
        assertNull(findings.get(3).cvss3ScoreNumeric());

        assertEquals("7.4", findings.get(5).cvss3Score());
        assertEquals(7.4, findings.get(5).cvss3ScoreNumeric());
    }

    @Test
    @DisplayName("scores arriving as JSON strings and JSON numbers both parse")
    void scoresParseFromBothRepresentations() {
        List<ActionableFinding> findings = map("actionable-scores-as-strings.json");

        assertEquals(9.8, findings.get(0).cvss3ScoreNumeric());
        assertEquals(7.5, findings.get(1).cvss3ScoreNumeric());
    }

    // ---------- nothing is lost ----------

    @ParameterizedTest
    @ValueSource(strings = {
            "actionable-full-detail.json",
            "actionable-minimal-fields.json",
            "actionable-null-nested.json",
            "actionable-scores-as-strings.json",
            "actionable-missing-coordinates.json",
            "actionable-no-library.json",
            "actionable-no-locations.json",
            "actionable-multiple-fixes.json",
            "actionable-null-fix-elements.json",
            "actionable-non-finite-scores.json",
            "actionable-hostile-text.json"
    })
    @DisplayName("no finding is dropped for any missing or awkward optional field")
    void noFindingIsEverDropped(String fixture) {
        List<VulnerabilityRecord> input = parse(fixture);
        List<ActionableFinding> mapped = ActionableReportMapper.toFindings(input);

        assertEquals(input.size(), mapped.size(),
                "mapping " + fixture + " changed the number of findings");
    }

    @Test
    @DisplayName("hostile text passes through unaltered at this stage")
    void hostileTextPassesThrough() {
        // The mapper does not escape or redact; those are the renderer's and redactor's jobs.
        ActionableFinding f = mapFirst("actionable-hostile-text.json");

        assertTrue(f.description().contains("|"));
        assertTrue(f.description().contains("\""));
        assertTrue(f.description().contains("\\"));
        assertTrue(f.description().contains("\n"));
        assertEquals("com.example.fake:example-fake-hostile:1.0.0", f.library().coordinates());
    }

    // ---------- input contract ----------

    @Test
    @DisplayName("a null list yields an empty result")
    void nullListYieldsEmpty() {
        assertTrue(ActionableReportMapper.toFindings(null).isEmpty());
        assertTrue(ActionableReportMapper.toFindings(List.of()).isEmpty());
    }

    @Test
    @DisplayName("a null element is ignored entirely, matching SeverityCounts")
    void nullInputElementIsIgnored() {
        // A null list element is not a vulnerability at all, so it must not become a finding --
        // that would inflate the finding count past SeverityCounts.total(), which ignores it the
        // same way, and ActionableReportFactory's consistency check would reject the report.
        List<VulnerabilityRecord> input = new ArrayList<>(Arrays.asList(
                new VulnerabilityRecord("high"), null, new VulnerabilityRecord("critical")));

        List<ActionableFinding> mapped = ActionableReportMapper.toFindings(input);

        assertEquals(2, mapped.size());
        assertEquals("HIGH", mapped.get(0).severity());
        assertEquals("CRITICAL", mapped.get(1).severity());
    }

    @Test
    @DisplayName("mapping a null record is rejected explicitly")
    void nullRecordRejected() {
        assertThrows(NullPointerException.class, () -> ActionableReportMapper.toFinding(null));
    }

    @Test
    @DisplayName("the returned list is immutable")
    void resultIsImmutable() {
        List<ActionableFinding> mapped =
                ActionableReportMapper.toFindings(List.of(new VulnerabilityRecord("high")));

        assertThrows(UnsupportedOperationException.class,
                () -> mapped.add(mapped.get(0)));
    }
}
