package com.tungsten.depbot.remediation;

import com.tungsten.depbot.report.actionable.ActionableFinding;
import com.tungsten.depbot.report.actionable.ActionableReport;
import com.tungsten.depbot.report.actionable.ActionableSummary;
import com.tungsten.depbot.report.actionable.AffectedLibrary;
import com.tungsten.depbot.report.actionable.RecommendedFix;
import com.tungsten.depbot.report.actionable.Remediation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemediationPlanBuilderTest {

    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-08-04T10:00:00Z"), ZoneOffset.UTC);

    private static AffectedLibrary library(String groupId, String artifactId, String version) {
        return new AffectedLibrary(groupId, artifactId, version, groupId + ":" + artifactId + ":" + version,
                artifactId, artifactId + "-" + version + ".jar", "JAVA", null, null, null, null, null);
    }

    private static Remediation remediationWithFixResolution(String fixResolution) {
        RecommendedFix fix = new RecommendedFix("CVE-TEST", "SOURCE_CODE_FIX", null, null, fixResolution, null, null);
        return new Remediation(fix, List.of());
    }

    private static ActionableFinding finding(
            String vulnerabilityId, String severity, AffectedLibrary lib, Remediation remediation) {
        return new ActionableFinding(vulnerabilityId, "CVE", severity, null, null, null, null, null,
                null, null, null, null, null, null, lib, List.of(), remediation);
    }

    private static ActionableReport reportOf(ActionableFinding... findings) {
        List<ActionableFinding> list = List.of(findings);
        return new ActionableReport("2026-08-04T09:00:00Z", "1.1",
                new ActionableSummary(list.size(), 0, 0, 0, 0, 0, list.size()), list);
    }

    @Test
    @DisplayName("multiple CVEs for the same library merge into one entry with all vulnerability ids")
    void mergesFindingsOfTheSameLibrary() {
        AffectedLibrary bcprov = library("org.bouncycastle", "bcprov-jdk18on", "1.84");
        ActionableFinding cve1 = finding("CVE-2026-1", "critical", bcprov,
                remediationWithFixResolution("Upgrade to version org.bouncycastle:bcprov-jdk18on:1.85"));
        ActionableFinding cve2 = finding("CVE-2026-2", "high", bcprov,
                remediationWithFixResolution("Upgrade to version org.bouncycastle:bcprov-jdk18on:1.85"));

        RemediationPlan plan = new RemediationPlanBuilder(FIXED_CLOCK).build(reportOf(cve1, cve2));

        assertEquals(1, plan.totalLibraries());
        assertEquals(1, plan.critical().size());
        LibraryRemediation entry = plan.critical().get(0);
        assertEquals("org.bouncycastle", entry.groupId());
        assertEquals("bcprov-jdk18on", entry.artifactId());
        assertEquals("1.84", entry.currentVersion());
        assertEquals("1.85", entry.targetVersion());
        assertEquals("CRITICAL", entry.maxSeverity());
        assertEquals(List.of("CVE-2026-1", "CVE-2026-2"), entry.vulnerabilityIds());
    }

    @Test
    @DisplayName("each of the four named severities places the library in its matching bucket")
    void placesLibrariesInMatchingBucket() {
        ActionableFinding critical = finding("CVE-1", "critical", library("g", "a1", "1.0"), Remediation.empty());
        ActionableFinding high = finding("CVE-2", "high", library("g", "a2", "1.0"), Remediation.empty());
        ActionableFinding medium = finding("CVE-3", "medium", library("g", "a3", "1.0"), Remediation.empty());
        ActionableFinding low = finding("CVE-4", "low", library("g", "a4", "1.0"), Remediation.empty());

        RemediationPlan plan = new RemediationPlanBuilder(FIXED_CLOCK).build(reportOf(critical, high, medium, low));

        assertEquals(1, plan.critical().size());
        assertEquals(1, plan.high().size());
        assertEquals(1, plan.medium().size());
        assertEquals(1, plan.low().size());
        assertTrue(plan.manualAnalysisRequired().isEmpty());
    }

    @Test
    @DisplayName("a library whose maximum severity is Other goes to manualAnalysisRequired, not Low")
    void otherSeverityGoesToManualAnalysisRequired() {
        ActionableFinding other = finding("CVE-1", "informational", library("g", "a", "1.0"), Remediation.empty());

        RemediationPlan plan = new RemediationPlanBuilder(FIXED_CLOCK).build(reportOf(other));

        assertTrue(plan.low().isEmpty());
        assertEquals(1, plan.manualAnalysisRequired().size());
        assertEquals("OTHER", plan.manualAnalysisRequired().get(0).maxSeverity());
    }

    @Test
    @DisplayName("the most severe CVE decides the bucket for a library with mixed severities")
    void mostSevereCveDecidesTheBucket() {
        AffectedLibrary lib = library("g", "a", "1.0");
        ActionableFinding low = finding("CVE-1", "low", lib, Remediation.empty());
        ActionableFinding critical = finding("CVE-2", "critical", lib, Remediation.empty());

        RemediationPlan plan = new RemediationPlanBuilder(FIXED_CLOCK).build(reportOf(low, critical));

        assertEquals(1, plan.critical().size());
        assertTrue(plan.low().isEmpty());
    }

    @Test
    @DisplayName("no target version resolvable marks the library MANUAL_ANALYSIS_REQUIRED but keeps its severity bucket")
    void unresolvableVersionIsMarkedButKeepsBucket() {
        ActionableFinding finding = finding("CVE-1", "critical", library("g", "a", "1.0"), Remediation.empty());

        RemediationPlan plan = new RemediationPlanBuilder(FIXED_CLOCK).build(reportOf(finding));

        assertEquals(1, plan.critical().size());
        assertEquals(TargetVersionResolver.MANUAL_ANALYSIS_REQUIRED, plan.critical().get(0).targetVersion());
    }

    @Test
    @DisplayName("the confirmed jackson-databind bug report resolves to the forward candidate 2.22.1, "
            + "not the downgrade 2.18.9, and stays in its real severity bucket")
    void jacksonDatabindBugReportResolvesForwardAndKeepsSeverityBucket() {
        AffectedLibrary jackson = library("com.fasterxml.jackson.core", "jackson-databind", "2.22.0");
        ActionableFinding cve1 = finding("CVE-2026-59889", "medium", jackson, remediationWithFixResolution(
                "Upgrade to version com.fasterxml.jackson.core:jackson-databind:2.21.5,"
                        + "com.fasterxml.jackson.core:jackson-databind:2.22.1,"
                        + "com.fasterxml.jackson.core:jackson-databind:2.18.9"));
        ActionableFinding cve2 = finding("CVE-2026-54515", "medium", jackson, remediationWithFixResolution(
                "Upgrade to version com.fasterxml.jackson.core:jackson-databind:2.21.5,"
                        + "com.fasterxml.jackson.core:jackson-databind:2.22.1,"
                        + "com.fasterxml.jackson.core:jackson-databind:2.18.9"));

        RemediationPlan plan = new RemediationPlanBuilder(FIXED_CLOCK).build(reportOf(cve1, cve2));

        assertEquals(1, plan.medium().size());
        LibraryRemediation entry = plan.medium().get(0);
        assertEquals("2.22.0", entry.currentVersion());
        assertEquals("2.22.1", entry.targetVersion());
        assertEquals(null, entry.manualAnalysisReason());
        assertTrue(plan.manualAnalysisRequired().isEmpty());
    }

    @Test
    @DisplayName("when every consistent fix candidate is at or below the current version, the library moves to "
            + "manualAnalysisRequired with a reason, regardless of its severity")
    void downgradeOnlyCandidatesGoToManualAnalysisRequiredWithReason() {
        AffectedLibrary jackson = library("com.fasterxml.jackson.core", "jackson-databind", "2.22.0");
        ActionableFinding cve1 = finding("CVE-1", "medium", jackson, remediationWithFixResolution(
                "Upgrade to version com.fasterxml.jackson.core:jackson-databind:2.18.9,"
                        + "com.fasterxml.jackson.core:jackson-databind:2.21.5,"
                        + "com.fasterxml.jackson.core:jackson-databind:2.22.0"));
        ActionableFinding cve2 = finding("CVE-2", "medium", jackson, remediationWithFixResolution(
                "Upgrade to version com.fasterxml.jackson.core:jackson-databind:2.21.5,"
                        + "com.fasterxml.jackson.core:jackson-databind:2.22.0"));

        RemediationPlan plan = new RemediationPlanBuilder(FIXED_CLOCK).build(reportOf(cve1, cve2));

        assertTrue(plan.medium().isEmpty(), "a downgrade-only result must never stay in its severity bucket");
        assertEquals(1, plan.manualAnalysisRequired().size());
        LibraryRemediation entry = plan.manualAnalysisRequired().get(0);
        assertEquals("jackson-databind", entry.artifactId());
        assertEquals(TargetVersionResolver.MANUAL_ANALYSIS_REQUIRED, entry.targetVersion());
        assertTrue(entry.manualAnalysisReason() != null && entry.manualAnalysisReason().contains("2.22.0"),
                entry.manualAnalysisReason());
        assertTrue(entry.manualAnalysisReason().toLowerCase(java.util.Locale.ROOT).contains("no forward fix"),
                entry.manualAnalysisReason());
    }

    @Test
    @DisplayName("no entry in any bucket ever carries a real target version at or below its current version")
    void noEntryEverCarriesADowngradeOrEqualTargetVersion() {
        AffectedLibrary forward = library("g", "forward-lib", "1.0.0");
        ActionableFinding forwardFinding = finding("CVE-1", "high", forward,
                remediationWithFixResolution("Upgrade to version g:forward-lib:1.2.0,g:forward-lib:1.1.0"));

        AffectedLibrary blocked = library("g", "blocked-lib", "2.22.0");
        ActionableFinding blockedFinding = finding("CVE-2", "low", blocked,
                remediationWithFixResolution("Upgrade to version g:blocked-lib:2.18.9,g:blocked-lib:2.22.0"));

        RemediationPlan plan = new RemediationPlanBuilder(FIXED_CLOCK).build(reportOf(forwardFinding, blockedFinding));

        for (LibraryRemediation entry : allEntries(plan)) {
            if (!TargetVersionResolver.MANUAL_ANALYSIS_REQUIRED.equals(entry.targetVersion())) {
                assertTrue(TargetVersionResolver.compareVersions(entry.targetVersion(), entry.currentVersion()) > 0,
                        entry.coordinates() + ": targetVersion " + entry.targetVersion()
                                + " must be strictly greater than currentVersion " + entry.currentVersion());
            }
        }
        assertEquals(1, plan.high().size());
        assertEquals("1.1.0", plan.high().get(0).targetVersion());
        assertEquals(1, plan.manualAnalysisRequired().size());
        assertEquals("blocked-lib", plan.manualAnalysisRequired().get(0).artifactId());
    }

    private static List<LibraryRemediation> allEntries(RemediationPlan plan) {
        List<LibraryRemediation> all = new ArrayList<>();
        all.addAll(plan.critical());
        all.addAll(plan.high());
        all.addAll(plan.medium());
        all.addAll(plan.low());
        all.addAll(plan.manualAnalysisRequired());
        return all;
    }

    @Test
    @DisplayName("a finding with no library at all is excluded without throwing")
    void findingWithoutLibraryIsExcluded() {
        ActionableFinding noLibrary = finding("CVE-1", "critical", null, Remediation.empty());

        RemediationPlan plan = new RemediationPlanBuilder(FIXED_CLOCK).build(reportOf(noLibrary));

        assertEquals(0, plan.totalLibraries());
    }

    @Test
    @DisplayName("a finding whose library is missing groupId or artifactId is excluded without throwing")
    void findingWithBlankCoordinatesIsExcluded() {
        AffectedLibrary blankGroupId = new AffectedLibrary(
                null, "a", "1.0", null, "a", "a.jar", "JAVA", null, null, null, null, null);
        ActionableFinding blankCoordinateFinding = finding("CVE-1", "critical", blankGroupId, Remediation.empty());

        RemediationPlan plan = new RemediationPlanBuilder(FIXED_CLOCK).build(reportOf(blankCoordinateFinding));

        assertEquals(0, plan.totalLibraries());
    }

    @Test
    @DisplayName("libraries within a bucket are sorted by groupId:artifactId")
    void librariesAreSortedWithinBucket() {
        ActionableFinding zLib = finding("CVE-1", "critical", library("g", "zzz", "1.0"), Remediation.empty());
        ActionableFinding aLib = finding("CVE-2", "critical", library("g", "aaa", "1.0"), Remediation.empty());

        RemediationPlan plan = new RemediationPlanBuilder(FIXED_CLOCK).build(reportOf(zLib, aLib));

        assertEquals("g:aaa", plan.critical().get(0).coordinates());
        assertEquals("g:zzz", plan.critical().get(1).coordinates());
    }

    @Test
    @DisplayName("generatedAt comes from the injected clock and sourceReportGeneratedAt is carried through")
    void timestampsComeFromClockAndSource() {
        RemediationPlan plan = new RemediationPlanBuilder(FIXED_CLOCK).build(reportOf());

        assertEquals("2026-08-04T10:00:00Z", plan.generatedAt());
        assertEquals("2026-08-04T09:00:00Z", plan.sourceReportGeneratedAt());
        assertEquals(RemediationPlan.CURRENT_VERSION, plan.reportVersion());
    }
}
