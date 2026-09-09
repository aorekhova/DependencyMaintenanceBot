package com.tungsten.depbot.mend;

import com.tungsten.depbot.Fixtures;
import com.tungsten.depbot.mend.model.MendFix;
import com.tungsten.depbot.mend.model.MendLibrary;
import com.tungsten.depbot.mend.model.MendLocation;
import com.tungsten.depbot.mend.model.VulnerabilityRecord;
import com.tungsten.depbot.mend.model.VulnerabilityReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that Mend's response binds onto the expanded integration model.
 *
 * <p>Several tests here deliberately assert Jackson's own behaviour rather than this project's
 * logic — notably that an absent JSON array becomes {@code null} rather than an empty list, and
 * that a JSON number binds onto a {@code String} component. Later checkpoints depend on both, so
 * pinning them means a future Jackson upgrade that changes either one fails loudly here instead of
 * quietly producing a wrong report.
 */
class MendModelBindingTest {

    private final MendResponseParser parser = new MendResponseParser();

    private VulnerabilityRecord single(String fixture) {
        VulnerabilityReport report = parser.parse(Fixtures.load(fixture));
        assertEquals(1, report.vulnerabilities().size(), "fixture should hold exactly one entry");
        return report.vulnerabilities().get(0);
    }

    // ---------- full detail ----------

    @Test
    @DisplayName("every top-level vulnerability field binds")
    void topLevelFieldsBind() {
        VulnerabilityRecord v = single("actionable-full-detail.json");

        assertEquals("FAKE-CVE-0000-0101", v.name());
        assertEquals("SECURITY_VULNERABILITY", v.type());
        assertEquals("high", v.severity());
        assertEquals("2020-01-15", v.publishDate());
        assertEquals("2020-06-30", v.lastUpdatedDate());
        assertEquals("FAKE/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", v.scoreMetadataVector());
        assertEquals("https://example.invalid/fake-advisory/0101", v.url());
        assertTrue(v.description().startsWith("Synthetic finding"));
        assertEquals("synthetic-test-project", v.project());
        assertEquals("synthetic-test-product", v.product());
    }

    @Test
    @DisplayName("snake_case CVSS 3 fields bind onto camelCase components")
    void snakeCaseCvssFieldsBind() {
        VulnerabilityRecord v = single("actionable-full-detail.json");

        assertEquals("high", v.cvss3Severity(), "cvss3_severity did not bind");
        assertEquals("8.1", v.cvss3Score(), "cvss3_score did not bind");
    }

    @Test
    @DisplayName("the library object binds in full")
    void libraryBinds() {
        MendLibrary library = single("actionable-full-detail.json").library();

        assertNotNull(library);
        assertEquals("com.example.fake", library.groupId());
        assertEquals("example-fake-lib-core", library.artifactId());
        assertEquals("1.0.0", library.version());
        assertEquals("example-fake-lib-core-1.0.0.jar", library.name());
        assertEquals("example-fake-lib-core-1.0.0.jar", library.filename());
        assertEquals("JAVA_ARCHIVE", library.type());
        assertEquals("0000000000000000000000000000000000000101", library.sha1());
        assertEquals("00000000-0000-0000-0000-000000000101", library.keyUuid());
        assertEquals("", library.architecture());
        assertEquals("", library.languageVersion());
    }

    @Test
    @DisplayName("topFix binds in full")
    void topFixBinds() {
        MendFix topFix = single("actionable-full-detail.json").topFix();

        assertNotNull(topFix);
        assertEquals("FAKE-CVE-0000-0101", topFix.vulnerability());
        assertEquals("UPGRADE_VERSION", topFix.type());
        assertEquals("EXAMPLE_FAKE_ADVISORY", topFix.origin());
        assertEquals("https://example.invalid/fake-fix/0101", topFix.url());
        assertEquals("com.example.fake:example-fake-lib-core:1.0.1", topFix.fixResolution());
        assertEquals("2020-07-01", topFix.date());
        assertEquals("Upgrade to a fixed version.", topFix.message());
    }

    @Test
    @DisplayName("every entry in allFixes binds, in order")
    void allFixesBind() {
        List<MendFix> fixes = single("actionable-full-detail.json").allFixes();

        assertEquals(2, fixes.size());
        assertEquals("UPGRADE_VERSION", fixes.get(0).type());
        assertEquals("CHANGE_FILES", fixes.get(1).type());
        assertEquals("Apply the synthetic patch file.", fixes.get(1).fixResolution());
    }

    @Test
    @DisplayName("every location binds, in order")
    void locationsBind() {
        List<MendLocation> locations = single("actionable-full-detail.json").locations();

        assertEquals(2, locations.size());
        assertEquals("EXACT_MATCH", locations.get(0).matchType());
        assertEquals("/synthetic/build/libs/example-fake-lib-core-1.0.0.jar",
                locations.get(0).path());
        assertEquals("FILENAME_MATCH", locations.get(1).matchType());
    }

    @Test
    @DisplayName("unknown fields such as cvss3Attributes are ignored, not rejected")
    void unknownFieldsIgnored() {
        // The full-detail fixture carries a cvss3Attributes object that this model does not map.
        assertNotNull(single("actionable-full-detail.json"));
    }

    // ---------- score coercion ----------

    @Test
    @DisplayName("a numeric JSON score binds onto a String component")
    void numericScoreBindsToString() {
        VulnerabilityRecord v = single("actionable-full-detail.json");

        assertEquals("8.1", v.score());
        assertEquals("8.1", v.cvss3Score());
    }

    @Test
    @DisplayName("scores bind whether Mend sends them as strings or numbers")
    void scoresBindFromBothRepresentations() {
        VulnerabilityReport report = parser.parse(Fixtures.load("actionable-scores-as-strings.json"));

        VulnerabilityRecord asString = report.vulnerabilities().get(0);
        VulnerabilityRecord asNumber = report.vulnerabilities().get(1);

        assertEquals("9.8", asString.cvss3Score());
        assertEquals("9.8", asString.score());
        assertEquals("7.5", asNumber.cvss3Score());
        assertEquals("7.5", asNumber.score());
    }

    // ---------- absent and null optionals ----------

    @Test
    @DisplayName("a minimal entry leaves every optional field null")
    void minimalEntryLeavesOptionalsNull() {
        VulnerabilityRecord v = single("actionable-minimal-fields.json");

        assertEquals("FAKE-CVE-0000-0201", v.name());
        assertEquals("critical", v.severity());
        assertNull(v.type());
        assertNull(v.score());
        assertNull(v.cvss3Severity());
        assertNull(v.cvss3Score());
        assertNull(v.publishDate());
        assertNull(v.lastUpdatedDate());
        assertNull(v.scoreMetadataVector());
        assertNull(v.url());
        assertNull(v.description());
        assertNull(v.project());
        assertNull(v.product());
        assertNull(v.library());
        assertNull(v.topFix());
    }

    @Test
    @DisplayName("ABSENT arrays bind to null, not to an empty list")
    void absentArraysBindToNull() {
        // Pinned deliberately: the report mapper must normalise these, and a future Jackson
        // change to empty-list defaults would otherwise silently alter report contents.
        VulnerabilityRecord v = single("actionable-minimal-fields.json");

        assertNull(v.allFixes(), "absent allFixes should bind to null");
        assertNull(v.locations(), "absent locations should bind to null");
    }

    @Test
    @DisplayName("explicit JSON nulls bind to null throughout")
    void explicitNullsBind() {
        VulnerabilityRecord v = single("actionable-null-nested.json");

        assertEquals("high", v.severity());
        assertNull(v.library());
        assertNull(v.topFix());
        assertNull(v.allFixes());
        assertNull(v.locations());
        assertNull(v.cvss3Score());
        assertNull(v.cvss3Severity());
        assertNull(v.description());
    }

    // ---------- compatibility with the severity-only constructor ----------

    @Test
    @DisplayName("the convenience constructor still yields a severity-only record")
    void convenienceConstructorStillWorks() {
        VulnerabilityRecord v = new VulnerabilityRecord("high");

        assertEquals("high", v.severity());
        assertNull(v.name());
        assertNull(v.library());
        assertNull(v.allFixes());
    }

    @Test
    @DisplayName("expanding the record did not break parsing the Slice 1 fixtures")
    void slice1FixturesStillParse() {
        VulnerabilityReport mixed = parser.parse(Fixtures.load("success-mixed-severities.json"));
        assertEquals(6, mixed.vulnerabilities().size());
        assertEquals("critical", mixed.vulnerabilities().get(0).severity());

        VulnerabilityReport empty = parser.parse(Fixtures.load("success-empty.json"));
        assertTrue(empty.vulnerabilities().isEmpty());

        VulnerabilityReport extra = parser.parse(Fixtures.load("success-extra-fields.json"));
        assertEquals(2, extra.vulnerabilities().size());
        // The Slice 1 fixture already carried a library object; it now binds instead of being dropped.
        assertNotNull(extra.vulnerabilities().get(0).library());
        assertEquals("com.example.fake", extra.vulnerabilities().get(0).library().groupId());
    }
}
