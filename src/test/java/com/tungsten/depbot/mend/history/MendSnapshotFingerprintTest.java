package com.tungsten.depbot.mend.history;

import com.tungsten.depbot.report.actionable.ActionableFinding;
import com.tungsten.depbot.report.actionable.AffectedLibrary;
import com.tungsten.depbot.report.actionable.RecommendedFix;
import com.tungsten.depbot.report.actionable.Remediation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class MendSnapshotFingerprintTest {

    private static AffectedLibrary library(String artifactId, String sha1) {
        return new AffectedLibrary("com.example", artifactId, "1.0.0",
                "com.example:" + artifactId + ":1.0.0", artifactId, artifactId + "-1.0.0.jar",
                "JAVA_ARCHIVE", sha1, "uuid-" + artifactId, "x86_64", "17", "a fake library");
    }

    private static RecommendedFix fix(String resolution) {
        return new RecommendedFix("vuln", "UPGRADE_VERSION", "MEND", "https://example.invalid/fix",
                resolution, "2020-01-01", "upgrade");
    }

    private static ActionableFinding finding(String id, String artifactId, String description,
            String publishedDate, String lastUpdatedDate) {
        return new ActionableFinding(id, "SECURITY_VULNERABILITY", "HIGH", "high", "8.1", 8.1,
                "8.1", "AV:N", description, publishedDate, lastUpdatedDate,
                "https://example.invalid/ref", "product", "project",
                library(artifactId, "0000000000000000000000000000000000000001"),
                List.of(), new Remediation(fix("com.example:" + artifactId + ":1.1.0"), List.of()));
    }

    private static ActionableFinding basicFinding(String id, String artifactId) {
        return finding(id, artifactId, "a description", "2020-01-01", "2020-02-02");
    }

    @Test
    @DisplayName("reordering findings does not change the fingerprint")
    void reorderedFindingsHashIdentically() {
        ActionableFinding a = basicFinding("CVE-1", "lib-a");
        ActionableFinding b = basicFinding("CVE-2", "lib-b");

        String forward = MendSnapshotFingerprint.compute(List.of(a, b));
        String reversed = MendSnapshotFingerprint.compute(List.of(b, a));

        assertEquals(forward, reversed);
    }

    @Test
    @DisplayName("changing only publishedDate/lastUpdatedDate never changes the fingerprint")
    void volatileDatesExcluded() {
        ActionableFinding original = finding("CVE-1", "lib-a", "desc", "2020-01-01", "2020-02-02");
        ActionableFinding touchedDates = finding("CVE-1", "lib-a", "desc", "2099-12-31", "2099-12-31");

        assertEquals(
                MendSnapshotFingerprint.compute(List.of(original)),
                MendSnapshotFingerprint.compute(List.of(touchedDates)));
    }

    @Test
    @DisplayName("changing locations never changes the fingerprint")
    void locationsExcluded() {
        ActionableFinding withLocation = new ActionableFinding("CVE-1", "SECURITY_VULNERABILITY", "HIGH",
                "high", "8.1", 8.1, "8.1", "AV:N", "a description", "2020-01-01", "2020-02-02",
                "https://example.invalid/ref", "product", "project",
                library("lib-a", "0000000000000000000000000000000000000001"),
                List.of(new com.tungsten.depbot.report.actionable.FindingLocation(
                        "/host/specific/path/lib-a.jar", "EXACT_MATCH")),
                new Remediation(fix("com.example:lib-a:1.1.0"), List.of()));
        ActionableFinding withoutLocation = basicFinding("CVE-1", "lib-a");
        // (withLocation differs from withoutLocation only in `locations`.)

        assertEquals(
                MendSnapshotFingerprint.compute(List.of(withLocation)),
                MendSnapshotFingerprint.compute(List.of(withoutLocation)));
    }

    @Test
    @DisplayName("changing any included field changes the fingerprint")
    void includedFieldChangesFingerprint() {
        ActionableFinding original = basicFinding("CVE-1", "lib-a");
        ActionableFinding changedDescription = finding("CVE-1", "lib-a", "a DIFFERENT description",
                "2020-01-01", "2020-02-02");

        assertNotEquals(
                MendSnapshotFingerprint.compute(List.of(original)),
                MendSnapshotFingerprint.compute(List.of(changedDescription)));
    }

    @Test
    @DisplayName("the same vulnerabilityId with different library coordinates never collides")
    void sameVulnerabilityIdDifferentCoordinatesNeverCollide() {
        ActionableFinding a = basicFinding("CVE-1", "lib-a");
        ActionableFinding b = basicFinding("CVE-1", "lib-b");

        assertNotEquals(
                MendSnapshotFingerprint.compute(List.of(a)),
                MendSnapshotFingerprint.compute(List.of(b)));
    }

    @Test
    @DisplayName("reordering allFixes does not change the fingerprint")
    void reorderedAllFixesHashIdentically() {
        RecommendedFix fixA = fix("com.example:lib-a:1.1.0");
        RecommendedFix fixB = fix("com.example:lib-a:1.2.0");

        ActionableFinding forward = new ActionableFinding("CVE-1", "SECURITY_VULNERABILITY", "HIGH",
                "high", "8.1", 8.1, "8.1", "AV:N", "desc", "2020-01-01", "2020-02-02",
                "https://example.invalid/ref", "product", "project",
                library("lib-a", "0000000000000000000000000000000000000001"), List.of(),
                new Remediation(fixA, List.of(fixA, fixB)));
        ActionableFinding reversed = new ActionableFinding("CVE-1", "SECURITY_VULNERABILITY", "HIGH",
                "high", "8.1", 8.1, "8.1", "AV:N", "desc", "2020-01-01", "2020-02-02",
                "https://example.invalid/ref", "product", "project",
                library("lib-a", "0000000000000000000000000000000000000001"), List.of(),
                new Remediation(fixA, List.of(fixB, fixA)));

        assertEquals(
                MendSnapshotFingerprint.compute(List.of(forward)),
                MendSnapshotFingerprint.compute(List.of(reversed)));
    }

    @Test
    @DisplayName("an empty finding list is deterministic")
    void emptyListDeterministic() {
        assertEquals(MendSnapshotFingerprint.compute(List.of()), MendSnapshotFingerprint.compute(List.of()));
    }
}
