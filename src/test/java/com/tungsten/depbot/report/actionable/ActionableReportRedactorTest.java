package com.tungsten.depbot.report.actionable;

import com.tungsten.depbot.Fixtures;
import com.tungsten.depbot.mend.MendResponseParser;
import com.tungsten.depbot.report.SecretRedactor;
import com.tungsten.depbot.report.SeverityCounts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.RecordComponent;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ActionableReportRedactorTest {

    private static final String MASK = SecretRedactor.MASK;

    // Deliberately awkward shapes. Each one defeats a different naive approach to redaction.
    private static final String SECRET_WITH_QUOTE = "SEC-quote\"inside-a1";
    private static final String SECRET_WITH_BACKSLASH = "SEC-back\\slash-b2";
    private static final String SECRET_WITH_NEWLINE = "SEC-new\nline-c3";
    private static final String SECRET_SHORT = "SEC-sub-d4";
    private static final String SECRET_LONG = "SEC-sub-d4-extended-e5";

    private static final List<String> ALL_SECRETS = List.of(
            SECRET_WITH_QUOTE, SECRET_WITH_BACKSLASH, SECRET_WITH_NEWLINE,
            SECRET_SHORT, SECRET_LONG);

    // ---------- helpers ----------

    private static AffectedLibrary library(String name, String description) {
        return new AffectedLibrary("com.example.fake", "example-fake-lib", "1.0.0",
                "com.example.fake:example-fake-lib:1.0.0", name, "example-fake-lib-1.0.0.jar",
                "JAVA_ARCHIVE", "0000000000000000000000000000000000000001",
                "00000000-0000-0000-0000-000000000001", "", "", description);
    }

    private static ActionableFinding finding(String description,
                                            AffectedLibrary library,
                                            List<FindingLocation> locations,
                                            Remediation remediation,
                                            String product,
                                            String project) {
        return new ActionableFinding("FAKE-CVE-0000-0001", "SECURITY_VULNERABILITY", "HIGH",
                "high", "8.1", 8.1, "8.1", "FAKE/AV:N", description, "2020-01-01", "2020-02-02",
                "https://example.invalid/a", product, project, library, locations, remediation);
    }

    private static ActionableReport reportWith(ActionableFinding finding) {
        return ActionableReport.of("2026-01-02T03:04:05Z",
                new ActionableSummary(1, 0, 1, 0, 0, 0, 1), List.of(finding));
    }

    /** Every string reachable anywhere in the report graph, found by reflection. */
    private static List<String> allStrings(Object root) {
        List<String> collected = new ArrayList<>();
        collect(root, collected, new IdentityHashMap<>());
        return collected;
    }

    private static void collect(Object value, List<String> out, Map<Object, Boolean> seen) {
        if (value == null) {
            return;
        }
        if (value instanceof String text) {
            out.add(text);
            return;
        }
        if (value instanceof Number || value instanceof Boolean) {
            return;
        }
        if (value instanceof Iterable<?> items) {
            for (Object item : items) {
                collect(item, out, seen);
            }
            return;
        }
        if (!value.getClass().isRecord() || seen.put(value, Boolean.TRUE) != null) {
            return;
        }
        for (RecordComponent component : value.getClass().getRecordComponents()) {
            try {
                collect(component.getAccessor().invoke(value), out, seen);
            } catch (ReflectiveOperationException e) {
                throw new IllegalStateException("could not read " + component.getName(), e);
            }
        }
    }

    private static void assertNoSecretAnywhere(ActionableReport redacted) {
        List<String> strings = allStrings(redacted);
        assertFalse(strings.isEmpty(), "the reflective sweep found nothing to check");

        for (String text : strings) {
            for (String secret : ALL_SECRETS) {
                assertFalse(text.contains(secret),
                        "secret survived redaction in field value: " + text);
            }
        }
    }

    // ---------- per-field masking ----------

    @Test
    @DisplayName("a secret in the description is masked")
    void descriptionMasked() {
        ActionableReport report = reportWith(finding(
                "Leaks " + SECRET_SHORT + " here", null, null, null, null, null));

        ActionableReport redacted = ActionableReportRedactor
                .withSecrets(SECRET_SHORT).redact(report);

        assertEquals("Leaks " + MASK + " here", redacted.findings().get(0).description());
    }

    @Test
    @DisplayName("secrets in library name and description are masked")
    void libraryFieldsMasked() {
        ActionableReport report = reportWith(finding(null,
                library("lib-" + SECRET_SHORT + ".jar", "note " + SECRET_LONG),
                null, null, null, null));

        AffectedLibrary redacted = ActionableReportRedactor
                .withSecrets(SECRET_SHORT, SECRET_LONG).redact(report).findings().get(0).library();

        assertFalse(redacted.name().contains(SECRET_SHORT));
        assertFalse(redacted.description().contains(SECRET_LONG));
        assertTrue(redacted.name().contains(MASK));
    }

    @Test
    @DisplayName("a secret in a location path is masked")
    void locationPathMasked() {
        ActionableReport report = reportWith(finding(null, null,
                List.of(new FindingLocation("/synthetic/" + SECRET_SHORT + "/a.jar", "EXACT_MATCH")),
                null, null, null));

        FindingLocation redacted = ActionableReportRedactor
                .withSecrets(SECRET_SHORT).redact(report).findings().get(0).locations().get(0);

        assertFalse(redacted.path().contains(SECRET_SHORT));
        assertEquals("EXACT_MATCH", redacted.matchType());
    }

    @Test
    @DisplayName("a secret in Mend-authored fix text is masked")
    void fixTextMasked() {
        RecommendedFix topFix = new RecommendedFix(null, "UPGRADE_VERSION", null, null,
                "com.example.fake:lib:1.0.1", null, "Upgrade. Token " + SECRET_SHORT + " leaked.");
        RecommendedFix alternative = new RecommendedFix(null, "CHANGE_FILES", null, null,
                "patch-" + SECRET_LONG, null, null);

        ActionableReport report = reportWith(finding(null, null, null,
                new Remediation(topFix, List.of(topFix, alternative)), null, null));

        Remediation redacted = ActionableReportRedactor
                .withSecrets(SECRET_SHORT, SECRET_LONG).redact(report)
                .findings().get(0).remediation();

        assertFalse(redacted.topFix().message().contains(SECRET_SHORT));
        assertTrue(redacted.topFix().message().contains(MASK));
        assertEquals(2, redacted.allFixes().size());
        assertFalse(redacted.allFixes().get(1).fixResolution().contains(SECRET_LONG));
    }

    @Test
    @DisplayName("secrets in product and project are masked")
    void productAndProjectMasked() {
        ActionableReport report = reportWith(finding(null, null, null, null,
                "product-" + SECRET_SHORT, "project-" + SECRET_SHORT));

        ActionableFinding redacted = ActionableReportRedactor
                .withSecrets(SECRET_SHORT).redact(report).findings().get(0);

        assertFalse(redacted.product().contains(SECRET_SHORT));
        assertFalse(redacted.project().contains(SECRET_SHORT));
    }

    // ---------- the hostile shapes ----------

    @Test
    @DisplayName("a secret containing a double quote is masked everywhere")
    void quoteBearingSecretMasked() {
        ActionableReport redacted = redactPlantedReport(SECRET_WITH_QUOTE);

        assertNoSecretAnywhere(redacted);
    }

    @Test
    @DisplayName("a secret containing a backslash is masked everywhere")
    void backslashBearingSecretMasked() {
        assertNoSecretAnywhere(redactPlantedReport(SECRET_WITH_BACKSLASH));
    }

    @Test
    @DisplayName("a secret containing a newline is masked everywhere")
    void newlineBearingSecretMasked() {
        assertNoSecretAnywhere(redactPlantedReport(SECRET_WITH_NEWLINE));
    }

    @Test
    @DisplayName("all four hostile shapes are masked in one pass")
    void allHostileShapesMaskedTogether() {
        ActionableReport report = plantEverywhere(
                SECRET_WITH_QUOTE, SECRET_WITH_BACKSLASH, SECRET_WITH_NEWLINE, SECRET_LONG);

        ActionableReport redacted = new ActionableReportRedactor(
                SecretRedactor.of(SECRET_WITH_QUOTE, SECRET_WITH_BACKSLASH,
                        SECRET_WITH_NEWLINE, SECRET_LONG, SECRET_SHORT)).redact(report);

        assertNoSecretAnywhere(redacted);
    }

    @Test
    @DisplayName("a secret that is a substring of another is fully masked, leaving no fragment")
    void substringSecretLeavesNoFragment() {
        // SECRET_SHORT is a prefix of SECRET_LONG. Masking the short one first would leave
        // "***-extended-e5" behind, exposing part of the longer credential.
        ActionableReport report = reportWith(finding(
                "long=" + SECRET_LONG + " short=" + SECRET_SHORT, null, null, null, null, null));

        String description = ActionableReportRedactor
                .withSecrets(SECRET_SHORT, SECRET_LONG).redact(report)
                .findings().get(0).description();

        assertEquals("long=" + MASK + " short=" + MASK, description);
        assertFalse(description.contains("extended"), "a fragment of the long secret survived");
    }

    private ActionableReport redactPlantedReport(String secret) {
        return ActionableReportRedactor.withSecrets(secret).redact(plantEverywhere(secret));
    }

    /** Builds a report with the given secrets planted into every text-bearing field. */
    private static ActionableReport plantEverywhere(String... secrets) {
        String blob = String.join(" / ", secrets);

        RecommendedFix fix = new RecommendedFix("vuln " + blob, "UPGRADE_VERSION " + blob,
                "origin " + blob, "https://example.invalid/" + blob, "resolution " + blob,
                "date " + blob, "message " + blob);

        return ActionableReport.of("2026-01-02T03:04:05Z",
                new ActionableSummary(1, 1, 0, 0, 0, 0, 1),
                List.of(new ActionableFinding(
                        "id " + blob, "type " + blob, "CRITICAL", "cvss3 " + blob,
                        "score " + blob, 9.9, "legacy " + blob, "vector " + blob,
                        "description " + blob, "published " + blob, "updated " + blob,
                        "https://example.invalid/ref/" + blob, "product " + blob,
                        "project " + blob,
                        library("name " + blob, "libdesc " + blob),
                        List.of(new FindingLocation("/path/" + blob, "match " + blob)),
                        new Remediation(fix, List.of(fix)))));
    }

    // ---------- realistic payload ----------

    @Test
    @DisplayName("the hostile-text fixture is fully redacted end to end")
    void hostileFixtureRedacted() {
        String userKey = "USERKEY-DO-NOT-LEAK-9f3a";
        String token = "TOKEN-DO-NOT-LEAK-7b1c";

        var vulnerabilities = new MendResponseParser()
                .parse(Fixtures.load("actionable-hostile-text.json"))
                .vulnerabilities();

        ActionableReport report = new ActionableReportFactory(
                Clock.fixed(Instant.parse("2026-01-02T03:04:05Z"), ZoneOffset.UTC))
                .build(vulnerabilities, SeverityCounts.from(vulnerabilities));

        // Before: the fixture deliberately embeds both synthetic credentials.
        List<String> before = allStrings(report);
        assertTrue(before.stream().anyMatch(s -> s.contains(token)),
                "fixture should contain the synthetic token before redaction");

        ActionableReport redacted =
                ActionableReportRedactor.withSecrets(userKey, token).redact(report);

        for (String text : allStrings(redacted)) {
            assertFalse(text.contains(userKey), "user key survived in: " + text);
            assertFalse(text.contains(token), "token survived in: " + text);
        }
    }

    // ---------- structure preserved ----------

    @Test
    @DisplayName("the input report is not modified")
    void inputReportUnchanged() {
        ActionableReport report = reportWith(finding(
                "keeps " + SECRET_SHORT, null, null, null, null, null));

        ActionableReportRedactor.withSecrets(SECRET_SHORT).redact(report);

        assertTrue(report.findings().get(0).description().contains(SECRET_SHORT),
                "redaction must not mutate the report it was given");
    }

    @Test
    @DisplayName("a no-op redactor leaves the report equal")
    void noOpRedactorLeavesReportEqual() {
        ActionableReport report = reportWith(finding("unchanged text",
                library("lib.jar", "note"),
                List.of(new FindingLocation("/a.jar", "EXACT_MATCH")),
                new Remediation(new RecommendedFix(null, "UPGRADE_VERSION", null, null,
                        "com.example.fake:lib:1.0.1", null, "msg"), List.of()),
                "product", "project"));

        assertEquals(report, ActionableReportRedactor.none().redact(report));
    }

    @Test
    @DisplayName("numeric and summary values are carried through untouched")
    void numericAndSummaryUntouched() {
        ActionableReport report = reportWith(finding(
                "text " + SECRET_SHORT, null, null, null, null, null));

        ActionableReport redacted = ActionableReportRedactor
                .withSecrets(SECRET_SHORT).redact(report);

        assertEquals(8.1, redacted.findings().get(0).cvss3ScoreNumeric());
        assertEquals(report.summary(), redacted.summary());
    }

    @Test
    @DisplayName("an absent library and empty collections survive redaction")
    void absentStructuresSurvive() {
        ActionableReport redacted = ActionableReportRedactor
                .withSecrets(SECRET_SHORT)
                .redact(reportWith(finding("text", null, null, null, null, null)));

        ActionableFinding finding = redacted.findings().get(0);
        assertNull(finding.library());
        assertNotNull(finding.locations());
        assertTrue(finding.locations().isEmpty());
        assertNotNull(finding.remediation());
        assertNull(finding.remediation().topFix());
        assertTrue(finding.remediation().allFixes().isEmpty());
    }

    @Test
    @DisplayName("redacted collections are still immutable")
    void redactedCollectionsAreImmutable() {
        ActionableReport redacted = ActionableReportRedactor
                .withSecrets(SECRET_SHORT)
                .redact(reportWith(finding("text", null,
                        List.of(new FindingLocation("/a.jar", "EXACT_MATCH")), null, null, null)));

        assertThrows(UnsupportedOperationException.class,
                () -> redacted.findings().get(0).locations()
                        .add(new FindingLocation("/b.jar", "EXACT_MATCH")));
    }

    @Test
    @DisplayName("an empty report redacts to an empty report")
    void emptyReportRedacts() {
        ActionableReport empty = ActionableReport.of("2026-01-02T03:04:05Z",
                new ActionableSummary(0, 0, 0, 0, 0, 0, 0), List.of());

        ActionableReport redacted = ActionableReportRedactor.withSecrets(SECRET_SHORT).redact(empty);

        assertTrue(redacted.findings().isEmpty());
        assertEquals("2026-01-02T03:04:05Z", redacted.generatedAt());
        assertEquals("1.1", redacted.reportVersion());
    }

    @Test
    @DisplayName("a realistic credential does not disturb the report metadata")
    void metadataUnaffectedByRealisticSecret() {
        ActionableReport report = reportWith(finding("text", null, null, null, null, null));

        ActionableReport redacted = ActionableReportRedactor
                .withSecrets("USERKEY-DO-NOT-LEAK-9f3a", "TOKEN-DO-NOT-LEAK-7b1c").redact(report);

        assertEquals("2026-01-02T03:04:05Z", redacted.generatedAt());
        assertEquals("1.1", redacted.reportVersion());
    }

    // ---------- contract ----------

    @Test
    @DisplayName("a null report redacts to null")
    void nullReportRedactsToNull() {
        assertNull(ActionableReportRedactor.withSecrets(SECRET_SHORT).redact(null));
    }

    @Test
    @DisplayName("a null SecretRedactor is rejected at construction")
    void nullRedactorRejected() {
        assertThrows(NullPointerException.class, () -> new ActionableReportRedactor(null));
    }

    // ---------- the sweep itself ----------

    @Test
    @DisplayName("the reflective sweep reaches every corner of the graph")
    void sweepIsNotVacuous() {
        List<String> strings = allStrings(plantEverywhere(SECRET_SHORT));

        // Finding 14 strings plus library 12, location 2 and two fixes at 7 each, plus metadata.
        assertTrue(strings.size() > 30,
                "expected the sweep to reach deep into the graph, found " + strings.size());
        assertTrue(strings.stream().anyMatch(s -> s.startsWith("/path/")),
                "sweep did not reach location paths");
        assertTrue(strings.stream().anyMatch(s -> s.startsWith("message ")),
                "sweep did not reach fix messages");
        assertTrue(strings.stream().anyMatch(s -> s.startsWith("libdesc ")),
                "sweep did not reach library descriptions");
    }
}
