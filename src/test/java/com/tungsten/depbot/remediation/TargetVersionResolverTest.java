package com.tungsten.depbot.remediation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TargetVersionResolverTest {

    @Test
    @DisplayName("extracts the version for the exact groupId:artifactId among sibling coordinates and a git URL")
    void extractsExactCoordinateAmongNoise() {
        String fixResolution = "Upgrade to version org.bouncycastle:bc-fips:2.0.2,"
                + "org.bouncycastle:bcprov-jdk18on:1.85,org.bouncycastle:bcprov-jdk15to18:1.85,"
                + "https://github.com/bcgit/bc-java.git - r1rv85";

        List<String> versions = TargetVersionResolver.extractVersions(
                "org.bouncycastle", "bcprov-jdk18on", fixResolution);

        assertEquals(List.of("1.85"), versions);
    }

    @Test
    @DisplayName("a fix mentioning only a different groupId or artifactId yields no match")
    void noMatchForDifferentArtifact() {
        String fixResolution = "Upgrade to version tools.jackson.core:jackson-databind:3.1.5";

        assertTrue(TargetVersionResolver
                .extractVersions("com.fasterxml.jackson.core", "jackson-databind", fixResolution)
                .isEmpty());
    }

    @Test
    @DisplayName("a git repository reference is never mistaken for a coordinate")
    void gitUrlIsNotAMatch() {
        String fixResolution = "https://github.com/apache/httpcomponents-core.git - rel/v5.4.3";

        assertTrue(TargetVersionResolver
                .extractVersions("org.apache.httpcomponents.core5", "httpcore5", fixResolution)
                .isEmpty());
    }

    @Test
    @DisplayName("multiple versions for the same CVE are all found")
    void multipleVersionsForOneCveAreAllFound() {
        String fixResolution = "Upgrade to version org.apache.httpcomponents.core5:httpcore5:5.4.3,"
                + "org.apache.httpcomponents.core5:httpcore5:5.5-beta2";

        List<String> versions = TargetVersionResolver.extractVersions(
                "org.apache.httpcomponents.core5", "httpcore5", fixResolution);

        assertEquals(List.of("5.4.3", "5.5-beta2"), versions);
    }

    @Test
    @DisplayName("stable candidates for a finding exclude pre-release versions")
    void stableCandidatesExcludePrerelease() {
        String fixResolution = "Upgrade to version org.apache.httpcomponents.core5:httpcore5:5.4.3,"
                + "org.apache.httpcomponents.core5:httpcore5:5.5-beta2";

        Set<String> stable = TargetVersionResolver.stableCandidatesForFinding(
                "org.apache.httpcomponents.core5", "httpcore5", List.of(fixResolution));

        assertEquals(Set.of("5.4.3"), stable);
    }

    @Test
    @DisplayName("isStable rejects beta, rc, alpha and SNAPSHOT qualifiers")
    void isStableRejectsPrereleaseQualifiers() {
        assertTrue(TargetVersionResolver.isStable("1.85"));
        assertTrue(TargetVersionResolver.isStable("2.22.1"));
        assertTrue(!TargetVersionResolver.isStable("5.5-beta2"));
        assertTrue(!TargetVersionResolver.isStable("1.0-rc1"));
        assertTrue(!TargetVersionResolver.isStable("1.0-alpha"));
        assertTrue(!TargetVersionResolver.isStable("1.0-SNAPSHOT"));
        assertTrue(!TargetVersionResolver.isStable(null));
    }

    @Test
    @DisplayName("resolve picks the minimum version present in every finding's candidate set")
    void resolvePicksMinimumOfIntersection() {
        Set<String> cve1 = new LinkedHashSet<>(Set.of("2.21.5", "2.22.1"));
        Set<String> cve2 = new LinkedHashSet<>(Set.of("2.21.5", "2.22.1"));

        assertEquals("2.21.5", TargetVersionResolver.resolve(List.of(cve1, cve2), "2.20.0"));
    }

    @Test
    @DisplayName("resolve picks the version required by the more restrictive CVE")
    void resolvePicksTheMoreRestrictiveVersion() {
        Set<String> cve1 = new LinkedHashSet<>(Set.of("2.21.5", "2.22.1"));
        Set<String> cve2 = new LinkedHashSet<>(Set.of("2.22.1"));

        assertEquals("2.22.1", TargetVersionResolver.resolve(List.of(cve1, cve2), "2.20.0"));
    }

    @Test
    @DisplayName("a single-CVE library with several stable options picks the smallest")
    void singleCveResolvesToItsSmallestStableOption() {
        Set<String> candidates = new LinkedHashSet<>(Set.of("2.25.5", "2.26.1"));

        assertEquals("2.25.5", TargetVersionResolver.resolve(List.of(candidates), "2.0.0"));
    }

    @Test
    @DisplayName("conflicting recommendations with no overlap require manual analysis")
    void conflictingRecommendationsRequireManualAnalysis() {
        Set<String> cve1 = new LinkedHashSet<>(Set.of("1.85"));
        Set<String> cve2 = new LinkedHashSet<>(Set.of("2.0.0"));

        assertEquals(TargetVersionResolver.MANUAL_ANALYSIS_REQUIRED,
                TargetVersionResolver.resolve(List.of(cve1, cve2), "1.0"));
    }

    @Test
    @DisplayName("a finding with no stable candidate at all requires manual analysis")
    void findingWithNoStableCandidateRequiresManualAnalysis() {
        Set<String> cve1 = new LinkedHashSet<>(Set.of("1.85"));
        Set<String> cve2 = Set.of();

        assertEquals(TargetVersionResolver.MANUAL_ANALYSIS_REQUIRED,
                TargetVersionResolver.resolve(List.of(cve1, cve2), "1.0"));
    }

    @Test
    @DisplayName("no findings at all requires manual analysis")
    void noFindingsRequiresManualAnalysis() {
        assertEquals(TargetVersionResolver.MANUAL_ANALYSIS_REQUIRED,
                TargetVersionResolver.resolve(List.of(), "1.0"));
    }

    @Test
    @DisplayName("the confirmed bug report: 2.22.0 plus {2.18.9, 2.21.5, 2.22.1} resolves to 2.22.1, never 2.18.9")
    void jacksonDatabindBugReportResolvesToForwardCandidate() {
        Set<String> candidates = new LinkedHashSet<>(Set.of("2.18.9", "2.21.5", "2.22.1"));

        assertEquals("2.22.1", TargetVersionResolver.resolve(List.of(candidates), "2.22.0"));
    }

    @Test
    @DisplayName("a candidate strictly below the current version is never picked, even as the global minimum")
    void candidateBelowCurrentVersionIsIgnored() {
        Set<String> candidates = new LinkedHashSet<>(Set.of("2.18.9", "2.22.1"));

        assertEquals("2.22.1", TargetVersionResolver.resolve(List.of(candidates), "2.22.0"));
    }

    @Test
    @DisplayName("a candidate exactly equal to the current version is never picked as the target")
    void candidateEqualToCurrentVersionIsIgnored() {
        Set<String> candidates = new LinkedHashSet<>(Set.of("2.22.0", "2.22.1"));

        assertEquals("2.22.1", TargetVersionResolver.resolve(List.of(candidates), "2.22.0"));
    }

    @Test
    @DisplayName("when every candidate is at or below the current version, the result is manual analysis, never a downgrade")
    void allCandidatesAtOrBelowCurrentVersionRequireManualAnalysis() {
        Set<String> candidates = new LinkedHashSet<>(Set.of("2.18.9", "2.21.5", "2.22.0"));

        String resolved = TargetVersionResolver.resolve(List.of(candidates), "2.22.0");

        assertEquals(TargetVersionResolver.MANUAL_ANALYSIS_REQUIRED, resolved);
    }

    @Test
    @DisplayName("the intersection across multiple CVEs is still honoured after forward-filtering")
    void intersectionAcrossMultipleCvesIsPreservedAfterForwardFiltering() {
        Set<String> cve1 = new LinkedHashSet<>(Set.of("2.18.9", "2.21.5", "2.22.1"));
        Set<String> cve2 = new LinkedHashSet<>(Set.of("2.21.5", "2.22.1"));

        // 2.18.9 is not in cve2's set at all, so it would never have been picked anyway; confirms
        // the pre-existing intersection step still runs before the new forward-only filter.
        assertEquals("2.21.5", TargetVersionResolver.resolve(List.of(cve1, cve2), "2.20.0"));
    }

    @Test
    @DisplayName("among several forward candidates the smallest one is chosen, not merely the first")
    void smallestForwardCandidateIsChosen() {
        Set<String> candidates = new LinkedHashSet<>(Set.of("2.10.0", "2.5.0", "2.3.0"));

        assertEquals("2.3.0", TargetVersionResolver.resolve(List.of(candidates), "2.0.0"));
    }

    @Test
    @DisplayName("a pre-release candidate above the current version is still excluded by isStable, forward or not")
    void prereleaseCandidateIsExcludedEvenWhenForward() {
        Set<String> stable = TargetVersionResolver.stableCandidatesForFinding(
                "org.apache.httpcomponents.core5", "httpcore5",
                List.of("Upgrade to version org.apache.httpcomponents.core5:httpcore5:5.4.3,"
                        + "org.apache.httpcomponents.core5:httpcore5:5.5-beta2"));

        assertEquals("5.4.3", TargetVersionResolver.resolve(List.of(stable), "5.2.5"));
    }

    @Test
    @DisplayName("an ordinary patch upgrade (1.84 -> 1.85) is unaffected by the forward-only filter")
    void ordinaryPatchUpgradeStillResolves() {
        Set<String> candidates = new LinkedHashSet<>(Set.of("1.85"));

        assertEquals("1.85", TargetVersionResolver.resolve(List.of(candidates), "1.84"));
    }

    @Test
    @DisplayName("intersectionOf returns the shared candidates across findings")
    void intersectionOfReturnsSharedCandidates() {
        Set<String> cve1 = new LinkedHashSet<>(Set.of("2.18.9", "2.21.5", "2.22.1"));
        Set<String> cve2 = new LinkedHashSet<>(Set.of("2.21.5", "2.22.1"));

        assertEquals(Set.of("2.21.5", "2.22.1"), TargetVersionResolver.intersectionOf(List.of(cve1, cve2)));
    }

    @Test
    @DisplayName("intersectionOf is empty when no findings are given")
    void intersectionOfIsEmptyForNoFindings() {
        assertTrue(TargetVersionResolver.intersectionOf(List.of()).isEmpty());
    }

    @Test
    @DisplayName("intersectionOf is empty as soon as one finding has no candidates at all")
    void intersectionOfIsEmptyWhenAnyFindingHasNoCandidates() {
        Set<String> cve1 = new LinkedHashSet<>(Set.of("1.85"));
        Set<String> cve2 = Set.of();

        assertTrue(TargetVersionResolver.intersectionOf(List.of(cve1, cve2)).isEmpty());
    }

    @Test
    @DisplayName("compareVersions orders numeric segments correctly, not lexicographically")
    void compareVersionsOrdersNumerically() {
        assertTrue(TargetVersionResolver.compareVersions("1.9", "1.10") < 0);
        assertTrue(TargetVersionResolver.compareVersions("2.22.1", "2.21.5") > 0);
        assertEquals(0, TargetVersionResolver.compareVersions("1.85", "1.85"));
    }

    @Test
    @DisplayName("compareVersions handles differing segment counts")
    void compareVersionsHandlesDifferingSegmentCounts() {
        assertTrue(TargetVersionResolver.compareVersions("1.85", "1.85.0") == 0);
        assertTrue(TargetVersionResolver.compareVersions("1.85.1", "1.85") > 0);
    }
}
