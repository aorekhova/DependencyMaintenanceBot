package com.tungsten.depbot.report.actionable;

import com.tungsten.depbot.Fixtures;
import com.tungsten.depbot.mend.MendResponseParser;
import com.tungsten.depbot.mend.model.VulnerabilityRecord;
import com.tungsten.depbot.report.SecretRedactor;
import com.tungsten.depbot.report.SeverityCounts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ActionableReportServiceTest {

    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-01-02T03:04:05Z"), ZoneOffset.UTC);

    private static final String USER_KEY = "USERKEY-DO-NOT-LEAK-9f3a";
    private static final String TOKEN = "TOKEN-DO-NOT-LEAK-7b1c";

    @TempDir
    Path reportDir;

    private ActionableReportService service() {
        return new ActionableReportService(FIXED_CLOCK, ReportDestination.into(reportDir));
    }

    private static List<VulnerabilityRecord> parse(String fixture) {
        return new MendResponseParser().parse(Fixtures.load(fixture)).vulnerabilities();
    }

    private WrittenReports generate(String fixture, ActionableReportService service) {
        List<VulnerabilityRecord> vulnerabilities = parse(fixture);
        return service.generate(vulnerabilities, SeverityCounts.from(vulnerabilities));
    }

    private static String read(Path path) throws IOException {
        return Files.readString(path, StandardCharsets.UTF_8);
    }

    // ---------- generation ----------

    @Test
    @DisplayName("both files are written and their paths returned")
    void bothFilesWritten() throws IOException {
        WrittenReports written = generate("actionable-full-detail.json", service());

        assertTrue(Files.exists(written.jsonPath()));
        assertTrue(Files.exists(written.markdownPath()));
        assertTrue(read(written.jsonPath()).contains("\"vulnerabilityId\" : \"FAKE-CVE-0000-0101\""));
        assertTrue(read(written.markdownPath()).contains("### 1. FAKE-CVE-0000-0101 - HIGH"));
    }

    @Test
    @DisplayName("both files carry the same generation stamp and version")
    void bothFilesShareGeneration() throws IOException {
        WrittenReports written = generate("actionable-full-detail.json", service());

        assertTrue(read(written.jsonPath()).contains("2026-01-02T03:04:05Z"));
        assertTrue(read(written.markdownPath()).contains("2026-01-02T03:04:05Z"));
        assertTrue(read(written.jsonPath()).contains("\"reportVersion\" : \"1.1\""));
        assertTrue(read(written.markdownPath()).contains("- Report version: 1.1"));
    }

    @Test
    @DisplayName("every severity reaches the findings, matching the summary totals")
    void everySeverityReachesFindingsAndSummary() throws IOException {
        WrittenReports written = generate("success-mixed-severities.json", service());
        String json = read(written.jsonPath());

        assertTrue(json.contains("\"totalVulnerabilities\" : 6"));
        assertTrue(json.contains("\"mediumCount\" : 1"));
        assertTrue(json.contains("\"actionableCount\" : 6"));
        assertEquals(6, read(written.markdownPath()).lines()
                .filter(line -> line.startsWith("### ")).count());
    }

    @Test
    @DisplayName("medium and low findings are written, not just counted")
    void mediumAndLowOnlyStillWritesFindings() throws IOException {
        List<VulnerabilityRecord> mediumOnly = List.of(
                new VulnerabilityRecord("medium"), new VulnerabilityRecord("low"));

        WrittenReports written =
                service().generate(mediumOnly, SeverityCounts.from(mediumOnly));

        assertTrue(Files.exists(written.jsonPath()));
        assertTrue(Files.exists(written.markdownPath()));
        assertFalse(read(written.jsonPath()).contains("\"findings\" : [ ]"),
                "medium/low findings must be listed, not filtered out");
        assertEquals(2, read(written.markdownPath()).lines()
                .filter(line -> line.startsWith("### ")).count());
        assertTrue(read(written.markdownPath()).contains("| Medium | 1 |"));
    }

    @Test
    @DisplayName("generating twice replaces both files")
    void generatingTwiceReplaces() throws IOException {
        generate("actionable-full-detail.json", service());
        WrittenReports second = generate("success-mixed-severities.json", service());

        assertTrue(read(second.jsonPath()).contains("\"totalVulnerabilities\" : 6"));
        assertFalse(read(second.jsonPath()).contains("FAKE-CVE-0000-0101"));
        try (var entries = Files.list(reportDir)) {
            // The current-scan JSON/Markdown pair (2), plus the new "mend-history/" snapshot store
            // (1) that now persists across scans -- see MendSnapshotHistoryServiceTest for its own
            // dedicated coverage of never physically duplicating an identical snapshot.
            assertEquals(3, entries.count());
        }
    }

    // ---------- redaction reaches both files ----------

    @Test
    @DisplayName("credentials are masked in both files, not just the console")
    void credentialsMaskedInBothFiles() throws IOException {
        WrittenReports written = generate("actionable-hostile-text.json",
                service().withSecrets(USER_KEY, TOKEN));

        String json = read(written.jsonPath());
        String markdown = read(written.markdownPath());

        assertFalse(json.contains(USER_KEY), "user key reached the JSON file");
        assertFalse(json.contains(TOKEN), "project token reached the JSON file");
        assertFalse(markdown.contains(USER_KEY), "user key reached the Markdown file");
        assertFalse(markdown.contains(TOKEN), "project token reached the Markdown file");
        assertTrue(json.contains(SecretRedactor.MASK));
        assertTrue(markdown.contains(SecretRedactor.MASK));
    }

    @ParameterizedTest
    @ValueSource(strings = {"SEC-quote\"inside-a1", "SEC-back\\slash-b2", "SEC-new\nline-c3"})
    @DisplayName("an awkwardly shaped secret is absent from both files")
    void awkwardSecretsAbsentFromBothFiles(String secret) throws IOException {
        VulnerabilityRecord record = new VulnerabilityRecord(
                "FAKE-CVE-0000-0001", null, "critical", null, null, "9.9", null, null, null,
                null, "leaks " + secret + " here", null, null, null, null, null, null);

        WrittenReports written = service().withSecrets(secret)
                .generate(List.of(record), SeverityCounts.from(List.of(record)));

        assertFalse(read(written.jsonPath()).contains(secret));
        assertFalse(read(written.markdownPath()).contains(secret));
    }

    @Test
    @DisplayName("withSecrets returns a new service and leaves the original unseeded")
    void withSecretsIsImmutable() throws IOException {
        ActionableReportService base = service();
        ActionableReportService secure = base.withSecrets(USER_KEY, TOKEN);

        assertTrue(base != secure);
        assertEquals(base.destination(), secure.destination());

        // The unseeded service does not redact, which is why the seeded one must be used.
        WrittenReports written = generate("actionable-hostile-text.json", base);
        assertTrue(read(written.jsonPath()).contains(TOKEN),
                "the base service should not redact; withSecrets is what does");
    }

    // ---------- invalidation ----------

    @Test
    @DisplayName("invalidating removes a previous pair")
    void invalidationRemovesPreviousPair() throws IOException {
        ReportDestination destination = ReportDestination.into(reportDir);
        Files.writeString(destination.jsonPath(), "PREVIOUS", StandardCharsets.UTF_8);
        Files.writeString(destination.markdownPath(), "PREVIOUS", StandardCharsets.UTF_8);

        service().invalidatePreviousReports();

        assertFalse(Files.exists(destination.jsonPath()));
        assertFalse(Files.exists(destination.markdownPath()));
    }

    @Test
    @DisplayName("invalidating an empty or missing directory is a silent success")
    void invalidationWithNothingToDo() {
        assertDoesNotThrow(() -> service().invalidatePreviousReports());
        assertDoesNotThrow(() -> new ActionableReportService(FIXED_CLOCK,
                ReportDestination.into(reportDir.resolve("absent"))).invalidatePreviousReports());
    }

    @Test
    @DisplayName("a blocked previous file makes invalidation fail")
    void blockedInvalidationFails() throws IOException {
        ReportDestination destination = ReportDestination.into(reportDir);
        Files.createDirectories(destination.jsonPath());
        Files.writeString(destination.jsonPath().resolve("occupant.txt"), "x",
                StandardCharsets.UTF_8);

        ReportWriteException thrown = assertThrows(ReportWriteException.class,
                () -> service().invalidatePreviousReports());

        assertFalse(thrown.pairStateGuaranteed());
    }

    // ---------- contract ----------

    @Test
    @DisplayName("null constructor arguments are rejected")
    void nullArgumentsRejected() {
        assertThrows(NullPointerException.class,
                () -> new ActionableReportService(null, ReportDestination.into(reportDir)));
        assertThrows(NullPointerException.class,
                () -> new ActionableReportService(FIXED_CLOCK, null));
        assertThrows(NullPointerException.class,
                () -> new ActionableReportService(FIXED_CLOCK, ReportDestination.into(reportDir),
                        null));
    }

    @Test
    @DisplayName("mismatched counts are rejected before anything is written")
    void mismatchedCountsWriteNothing() throws IOException {
        List<VulnerabilityRecord> input = List.of(new VulnerabilityRecord("high"));

        assertThrows(IllegalStateException.class,
                () -> service().generate(input, new SeverityCounts(9, 4, 5, 0, 0, 0)));

        try (var entries = Files.list(reportDir)) {
            assertEquals(0, entries.count(), "a rejected report must not leave files behind");
        }
    }

    // ---------- Mend snapshot history ----------

    @Test
    @DisplayName("the generated report is stamped with the recorded snapshot's fingerprint")
    void reportIsStampedWithSnapshotFingerprint() throws IOException {
        WrittenReports written = generate("actionable-full-detail.json", service());

        String json = read(written.jsonPath());
        assertTrue(json.contains("\"sourceSnapshotFingerprint\" : \""),
                "the published report must reference the exact snapshot it was built from");
        assertFalse(json.contains("\"sourceSnapshotFingerprint\" : null"));
    }

    @Test
    @DisplayName("two scans of identical content share one snapshot file and the same fingerprint")
    void identicalScansShareOneSnapshot() throws IOException {
        WrittenReports first = generate("actionable-full-detail.json", service());
        WrittenReports second = generate("actionable-full-detail.json", service());

        String fingerprint1 = fingerprintOf(read(first.jsonPath()));
        String fingerprint2 = fingerprintOf(read(second.jsonPath()));
        assertEquals(fingerprint1, fingerprint2, "an identical snapshot must fingerprint identically");

        Path snapshotsDir = reportDir.resolve("mend-history").resolve("snapshots");
        try (var entries = Files.list(snapshotsDir)) {
            assertEquals(1, entries.count(),
                    "an identical snapshot must never be physically duplicated on disk");
        }
    }

    @Test
    @DisplayName("two scans of different content produce two distinct, preserved snapshots")
    void differentScansProduceDistinctSnapshots() throws IOException {
        generate("actionable-full-detail.json", service());
        generate("success-mixed-severities.json", service());

        Path snapshotsDir = reportDir.resolve("mend-history").resolve("snapshots");
        try (var entries = Files.list(snapshotsDir)) {
            assertEquals(2, entries.count(), "genuinely different content must get its own snapshot");
        }
    }

    @Test
    @DisplayName("the persisted snapshot never carries a secret -- fingerprinting happens after redaction")
    void persistedSnapshotNeverCarriesASecret() throws IOException {
        generate("actionable-hostile-text.json", service().withSecrets(USER_KEY, TOKEN));

        Path snapshotsDir = reportDir.resolve("mend-history").resolve("snapshots");
        try (var entries = Files.list(snapshotsDir)) {
            for (Path snapshotFile : entries.toList()) {
                String content = read(snapshotFile);
                assertFalse(content.contains(USER_KEY), "user key survived into the history snapshot");
                assertFalse(content.contains(TOKEN), "token survived into the history snapshot");
                assertTrue(content.contains(SecretRedactor.MASK),
                        "the persisted snapshot must reflect the redacted content, not skip it");
            }
        }
    }

    private static String fingerprintOf(String json) {
        String marker = "\"sourceSnapshotFingerprint\" : \"";
        int start = json.indexOf(marker) + marker.length();
        int end = json.indexOf('"', start);
        return json.substring(start, end);
    }
}
