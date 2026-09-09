package com.tungsten.depbot.report.actionable;

import com.tungsten.depbot.Fixtures;
import com.tungsten.depbot.mend.MendResponseParser;
import com.tungsten.depbot.mend.model.VulnerabilityRecord;
import com.tungsten.depbot.report.SeverityCounts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ActionableReportFactoryTest {

    private static final Instant FIXED_INSTANT = Instant.parse("2026-01-02T03:04:05Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(FIXED_INSTANT, ZoneOffset.UTC);

    private final ActionableReportFactory factory = new ActionableReportFactory(FIXED_CLOCK);

    private static VulnerabilityRecord record(String id, String severity, String cvss3Score) {
        return new VulnerabilityRecord(id, null, severity, null, null, cvss3Score, null, null,
                null, null, null, null, null, null, null, null, null);
    }

    private static List<String> idsOf(ActionableReport report) {
        return report.findings().stream().map(ActionableFinding::vulnerabilityId).toList();
    }

    /** Builds a report from a list, deriving the counts from that same list as production does. */
    private ActionableReport buildFrom(List<VulnerabilityRecord> input) {
        return factory.build(input, SeverityCounts.from(input));
    }

    // ---------- timestamp ----------

    @Test
    @DisplayName("a fixed clock produces an exact, deterministic generatedAt")
    void fixedClockProducesExactTimestamp() {
        assertEquals("2026-01-02T03:04:05Z", buildFrom(List.of()).generatedAt());
    }

    @Test
    @DisplayName("two builds with the same clock are identical")
    void repeatedBuildsAreIdentical() {
        List<VulnerabilityRecord> input = List.of(
                record("FAKE-CVE-0000-0001", "critical", "9.9"),
                record("FAKE-CVE-0000-0002", "high", "7.1"));

        ActionableReport first = buildFrom(input);
        ActionableReport second = buildFrom(input);

        assertEquals(first.generatedAt(), second.generatedAt());
        assertEquals(first, second, "the same input and clock must produce an identical report");
    }

    @Test
    @DisplayName("sub-second precision is truncated away")
    void timestampTruncatedToSeconds() {
        Clock withNanos = Clock.fixed(Instant.parse("2026-01-02T03:04:05.987654321Z"),
                ZoneOffset.UTC);

        String generatedAt = new ActionableReportFactory(withNanos)
                .build(List.of(), SeverityCounts.from(List.of()))
                .generatedAt();

        assertEquals("2026-01-02T03:04:05Z", generatedAt);
        assertFalse(generatedAt.contains("."), "generatedAt should carry no fractional seconds");
    }

    @Test
    @DisplayName("the production factory uses a UTC clock")
    void systemUtcFactory() {
        ActionableReport report = ActionableReportFactory.systemUtc()
                .build(List.of(), SeverityCounts.from(List.of()));

        assertTrue(report.generatedAt().endsWith("Z"),
                "expected a UTC instant, got " + report.generatedAt());
    }

    @Test
    @DisplayName("a null clock is rejected at construction")
    void nullClockRejected() {
        assertThrows(NullPointerException.class, () -> new ActionableReportFactory(null));
    }

    // ---------- schema ----------

    @Test
    @DisplayName("the report carries the current schema version")
    void reportVersionIsStamped() {
        assertEquals("1.1", buildFrom(List.of()).reportVersion());
    }

    // ---------- summary ----------

    @Test
    @DisplayName("the summary mirrors the supplied counts exactly")
    void summaryMirrorsCounts() {
        List<VulnerabilityRecord> input = List.of(
                record("FAKE-C1", "critical", "9.9"),
                record("FAKE-H1", "high", "8.0"),
                record("FAKE-H2", "HIGH", "7.0"),
                record("FAKE-M1", "medium", "5.0"),
                record("FAKE-M2", "medium", "4.0"),
                record("FAKE-L1", "low", "2.0"),
                record("FAKE-O1", "informational", null));

        SeverityCounts counts = SeverityCounts.from(input);
        ActionableSummary summary = factory.build(input, counts).summary();

        assertEquals(counts.total(), summary.totalVulnerabilities());
        assertEquals(counts.criticalCount(), summary.criticalCount());
        assertEquals(counts.highCount(), summary.highCount());
        assertEquals(counts.mediumCount(), summary.mediumCount());
        assertEquals(counts.lowCount(), summary.lowCount());
        assertEquals(counts.otherCount(), summary.otherCount());
    }

    @Test
    @DisplayName("the total still equals the sum of every bucket")
    void totalInvariantHolds() {
        List<VulnerabilityRecord> input = List.of(
                record("FAKE-C1", "critical", "9.9"),
                record("FAKE-H1", "high", "8.0"),
                record("FAKE-M1", "medium", "5.0"),
                record("FAKE-L1", "low", "2.0"),
                record("FAKE-O1", "unknown-severity", null));

        ActionableSummary summary = buildFrom(input).summary();

        assertEquals(5, summary.totalVulnerabilities());
        assertEquals(summary.totalVulnerabilities(), summary.sumOfBuckets());
    }

    @Test
    @DisplayName("actionableCount now always equals the total, since every severity is included")
    void actionableCountIsConsistent() {
        List<VulnerabilityRecord> input = List.of(
                record("FAKE-C1", "critical", "9.9"),
                record("FAKE-H1", "high", "8.0"),
                record("FAKE-H2", "high", "7.0"),
                record("FAKE-M1", "medium", "5.0"));

        ActionableReport report = buildFrom(input);

        assertEquals(4, report.summary().actionableCount());
        assertEquals(report.findings().size(), report.summary().actionableCount());
        assertEquals(report.summary().totalVulnerabilities(), report.summary().actionableCount());
    }

    // ---------- every severity reaches the findings ----------

    @Test
    @DisplayName("every severity — critical, high, medium and low — reaches the findings")
    void everySeverityAppearsInFindings() {
        List<VulnerabilityRecord> input = List.of(
                record("FAKE-C1", "critical", "9.9"),
                record("FAKE-H1", "high", "8.5"),
                record("FAKE-H2", "high", "8.0"),
                record("FAKE-H3", "high", "7.5"),
                record("FAKE-M1", "medium", "6.0"),
                record("FAKE-M2", "medium", "5.0"),
                record("FAKE-L1", "low", "2.0"));

        ActionableReport report = buildFrom(input);

        assertEquals(7, report.summary().totalVulnerabilities());
        assertEquals(2, report.summary().mediumCount());
        assertEquals(1, report.summary().lowCount());

        // Nothing is filtered any more: the finding count matches the total, and the sort order
        // (severity, then descending score) puts Critical first and Low last.
        assertEquals(7, report.findings().size());
        assertEquals(
                List.of("FAKE-C1", "FAKE-H1", "FAKE-H2", "FAKE-H3", "FAKE-M1", "FAKE-M2", "FAKE-L1"),
                idsOf(report));
    }

    @Test
    @DisplayName("a scan with no critical or high findings still lists everything it has")
    void mediumAndLowOnlyScanStillListsThem() {
        List<VulnerabilityRecord> input = List.of(
                record("FAKE-M1", "medium", "5.0"),
                record("FAKE-L1", "low", "2.0"),
                record("FAKE-O1", "informational", null));

        ActionableReport report = buildFrom(input);

        assertFalse(report.findings().isEmpty(), "medium/low/other findings must still be listed");
        assertTrue(report.hasActionableFindings());
        assertEquals(3, report.findings().size());
        assertEquals(3, report.summary().actionableCount());
        assertEquals(3, report.summary().totalVulnerabilities());
        assertEquals("1.1", report.reportVersion());
        assertEquals("2026-01-02T03:04:05Z", report.generatedAt());
    }

    @Test
    @DisplayName("an empty scan produces a valid zero report")
    void emptyScanIsValid() {
        ActionableReport report = buildFrom(List.of());

        assertTrue(report.findings().isEmpty());
        assertEquals(0, report.summary().totalVulnerabilities());
        assertEquals(0, report.summary().sumOfBuckets());
    }

    @Test
    @DisplayName("a null vulnerability list is treated as an empty scan")
    void nullListIsTreatedAsEmpty() {
        ActionableReport report = factory.build(null, SeverityCounts.from(null));

        assertTrue(report.findings().isEmpty());
        assertEquals(0, report.summary().totalVulnerabilities());
    }

    @Test
    @DisplayName("a null element is ignored entirely, keeping the total and findings consistent")
    void nullElementIsIgnoredEntirely() {
        List<VulnerabilityRecord> input = new ArrayList<>(Arrays.asList(
                record("FAKE-C1", "critical", "9.9"), null, record("FAKE-H1", "high", "8.0")));

        ActionableReport report = buildFrom(input);

        assertEquals(2, report.summary().totalVulnerabilities());
        assertEquals(0, report.summary().otherCount(), "the null element must not count as other");
        // Findings must match the total exactly, or the report would contradict the summary.
        assertEquals(2, report.findings().size());
        assertTrue(idsOf(report).contains("FAKE-C1"));
        assertTrue(idsOf(report).contains("FAKE-H1"));
    }

    // ---------- ordering through the factory ----------

    @Test
    @DisplayName("findings come out in the documented order")
    void findingsAreSorted() {
        List<VulnerabilityRecord> input = List.of(
                record("FAKE-H2", "high", "7.5"),
                record("FAKE-H4", "high", null),
                record("FAKE-C2", "critical", "9.1"),
                record("FAKE-H1", "high", "8.8"),
                record("FAKE-C1", "critical", "9.9"),
                record("FAKE-H3", "high", "7.5"));

        assertEquals(
                List.of("FAKE-C1", "FAKE-C2", "FAKE-H1", "FAKE-H2", "FAKE-H3", "FAKE-H4"),
                idsOf(buildFrom(input)));
    }

    @Test
    @DisplayName("a non-finite score does not get promoted to the top of the report")
    void nonFiniteScoreNotPromoted() {
        List<VulnerabilityRecord> input = List.of(
                record("FAKE-BROKEN", "high", "NaN"),
                record("FAKE-REAL", "high", "1.0"));

        assertEquals(List.of("FAKE-REAL", "FAKE-BROKEN"), idsOf(buildFrom(input)));
    }

    @Test
    @DisplayName("findings are immutable")
    void findingsAreImmutable() {
        ActionableReport report = buildFrom(List.of(record("FAKE-C1", "critical", "9.9")));

        assertThrows(UnsupportedOperationException.class,
                () -> report.findings().add(report.findings().get(0)));
    }

    // ---------- consistency guard ----------

    @Test
    @DisplayName("counts from a different scan are rejected rather than silently reported")
    void mismatchedCountsRejected() {
        List<VulnerabilityRecord> input = List.of(record("FAKE-H1", "high", "8.0"));
        // total, critical, high, medium, low, other -- claims 9 actionable against 1 real finding.
        SeverityCounts countsFromAnotherScan = new SeverityCounts(9, 4, 5, 0, 0, 0);

        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> factory.build(input, countsFromAnotherScan));

        assertTrue(thrown.getMessage().contains("contradict"),
                "the message should explain the inconsistency: " + thrown.getMessage());
    }

    @Test
    @DisplayName("null counts are rejected")
    void nullCountsRejected() {
        assertThrows(NullPointerException.class, () -> factory.build(List.of(), null));
    }

    // ---------- realistic end to end ----------

    @Test
    @DisplayName("a realistic Mend payload maps into a complete report")
    void realisticPayloadBuildsFullReport() {
        List<VulnerabilityRecord> input = new MendResponseParser()
                .parse(Fixtures.load("actionable-full-detail.json"))
                .vulnerabilities();

        ActionableReport report = buildFrom(input);

        assertEquals(1, report.findings().size());
        ActionableFinding finding = report.findings().get(0);

        assertEquals("FAKE-CVE-0000-0101", finding.vulnerabilityId());
        assertEquals("HIGH", finding.severity());
        assertEquals(8.1, finding.cvss3ScoreNumeric());
        assertEquals("com.example.fake:example-fake-lib-core:1.0.0",
                finding.library().coordinates());
        assertEquals(2, finding.locations().size());
        assertEquals(2, finding.remediation().allFixes().size());
        assertEquals("com.example.fake:example-fake-lib-core:1.0.1",
                finding.remediation().topFix().fixResolution());

        assertEquals(1, report.summary().totalVulnerabilities());
        assertEquals(1, report.summary().highCount());
        assertEquals(1, report.summary().actionableCount());
    }

    @Test
    @DisplayName("a mixed severity fixture keeps every entry in both the summary and the findings")
    void mixedFixtureSummaryComplete() {
        List<VulnerabilityRecord> input = new MendResponseParser()
                .parse(Fixtures.load("success-mixed-severities.json"))
                .vulnerabilities();

        ActionableReport report = buildFrom(input);

        // The Slice 1 fixture holds 1 critical, 2 high, 1 medium, 1 low and 1 unrecognised.
        assertEquals(6, report.summary().totalVulnerabilities());
        assertEquals(6, report.summary().sumOfBuckets());
        assertEquals(6, report.findings().size());
        assertEquals(6, report.summary().actionableCount());
        assertEquals(
                List.of("CRITICAL", "HIGH", "HIGH", "MEDIUM", "LOW", "OTHER"),
                report.findings().stream().map(ActionableFinding::severity).toList());
    }
}
