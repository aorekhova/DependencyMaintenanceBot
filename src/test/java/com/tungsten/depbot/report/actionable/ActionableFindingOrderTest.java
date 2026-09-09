package com.tungsten.depbot.report.actionable;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ActionableFindingOrderTest {

    /** A finding carrying only what the ordering looks at. */
    private static ActionableFinding finding(String severity, Double score, String id,
                                            String coordinates) {
        AffectedLibrary library = coordinates == null
                ? null
                : new AffectedLibrary(null, null, null, coordinates, null, null, null, null,
                        null, null, null, null);

        return new ActionableFinding(id, null, severity, null, null, score, null, null, null,
                null, null, null, null, null, library, null, null);
    }

    private static ActionableFinding finding(String severity, Double score, String id) {
        return finding(severity, score, id, null);
    }

    private static List<String> idsOf(List<ActionableFinding> findings) {
        return findings.stream().map(ActionableFinding::vulnerabilityId).toList();
    }

    // ---------- level 1: severity ----------

    @Test
    @DisplayName("CRITICAL sorts before HIGH even when HIGH has the higher score")
    void criticalBeforeHighRegardlessOfScore() {
        List<ActionableFinding> sorted = ActionableFindingOrder.sorted(List.of(
                finding("HIGH", 10.0, "FAKE-HIGH"),
                finding("CRITICAL", 0.1, "FAKE-CRIT")));

        assertEquals(List.of("FAKE-CRIT", "FAKE-HIGH"), idsOf(sorted));
    }

    @Test
    @DisplayName("severity ordering is case-insensitive")
    void severityOrderingIsCaseInsensitive() {
        List<ActionableFinding> sorted = ActionableFindingOrder.sorted(List.of(
                finding("high", 5.0, "FAKE-A"),
                finding("critical", 5.0, "FAKE-B")));

        assertEquals(List.of("FAKE-B", "FAKE-A"), idsOf(sorted));
    }

    @Test
    @DisplayName("all five severities sort correctly together, not just in pairwise isolation")
    void allFiveSeveritiesSortTogether() {
        // Now that the detailed report includes every severity, this is a real scenario, not just
        // a theoretical extension of the Severity enum's declaration order.
        List<ActionableFinding> sorted = ActionableFindingOrder.sorted(List.of(
                finding("OTHER", 1.0, "FAKE-OTHER"),
                finding("LOW", 3.0, "FAKE-LOW"),
                finding("MEDIUM", 6.0, "FAKE-MEDIUM"),
                finding("CRITICAL", 9.0, "FAKE-CRITICAL"),
                finding("HIGH", 8.0, "FAKE-HIGH")));

        assertEquals(
                List.of("FAKE-CRITICAL", "FAKE-HIGH", "FAKE-MEDIUM", "FAKE-LOW", "FAKE-OTHER"),
                idsOf(sorted));
    }

    // ---------- level 2: score, descending ----------

    @Test
    @DisplayName("within a severity, higher scores come first")
    void higherScoreFirst() {
        List<ActionableFinding> sorted = ActionableFindingOrder.sorted(List.of(
                finding("HIGH", 7.1, "FAKE-MID"),
                finding("HIGH", 8.9, "FAKE-TOP"),
                finding("HIGH", 7.0, "FAKE-LOW")));

        assertEquals(List.of("FAKE-TOP", "FAKE-MID", "FAKE-LOW"), idsOf(sorted));
    }

    @Test
    @DisplayName("a missing score sorts after every present score")
    void missingScoreLast() {
        List<ActionableFinding> sorted = ActionableFindingOrder.sorted(List.of(
                finding("HIGH", null, "FAKE-NONE"),
                finding("HIGH", 0.1, "FAKE-TINY")));

        assertEquals(List.of("FAKE-TINY", "FAKE-NONE"), idsOf(sorted));
    }

    @ParameterizedTest
    @ValueSource(doubles = {Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY})
    @DisplayName("non-finite scores are treated as missing and never promoted to the top")
    void nonFiniteScoresTreatedAsMissing(double nonFinite) {
        // Java orders NaN above every real number, so without the finite guard a corrupt score
        // would take the most prominent position in the report.
        List<ActionableFinding> sorted = ActionableFindingOrder.sorted(List.of(
                finding("HIGH", nonFinite, "FAKE-BROKEN"),
                finding("HIGH", 1.0, "FAKE-REAL")));

        assertEquals(List.of("FAKE-REAL", "FAKE-BROKEN"), idsOf(sorted),
                "non-finite score " + nonFinite + " should sort last");
    }

    @Test
    @DisplayName("all three non-finite values tie with each other and with a missing score")
    void nonFiniteValuesTieWithMissing() {
        List<ActionableFinding> sorted = ActionableFindingOrder.sorted(List.of(
                finding("HIGH", Double.NaN, "FAKE-D"),
                finding("HIGH", Double.NEGATIVE_INFINITY, "FAKE-C"),
                finding("HIGH", null, "FAKE-B"),
                finding("HIGH", Double.POSITIVE_INFINITY, "FAKE-A")));

        // All four are scoreless, so the tie falls through to the id level.
        assertEquals(List.of("FAKE-A", "FAKE-B", "FAKE-C", "FAKE-D"), idsOf(sorted));
    }

    // ---------- level 3: vulnerability id ----------

    @Test
    @DisplayName("equal severity and score fall through to the id, ascending")
    void tieBrokenByVulnerabilityId() {
        List<ActionableFinding> sorted = ActionableFindingOrder.sorted(List.of(
                finding("HIGH", 8.1, "FAKE-CVE-0000-0003"),
                finding("HIGH", 8.1, "FAKE-CVE-0000-0001"),
                finding("HIGH", 8.1, "FAKE-CVE-0000-0002")));

        assertEquals(List.of("FAKE-CVE-0000-0001", "FAKE-CVE-0000-0002", "FAKE-CVE-0000-0003"),
                idsOf(sorted));
    }

    @Test
    @DisplayName("a missing id sorts after a present one")
    void missingIdLast() {
        List<ActionableFinding> sorted = ActionableFindingOrder.sorted(List.of(
                finding("HIGH", 8.1, null),
                finding("HIGH", 8.1, "FAKE-CVE-0000-0009")));

        // Arrays.asList, not List.of: the latter rejects null elements.
        assertEquals(Arrays.asList("FAKE-CVE-0000-0009", null), idsOf(sorted));
    }

    // ---------- level 4: library coordinates ----------

    @Test
    @DisplayName("equal severity, score and id fall through to coordinates, ascending")
    void tieBrokenByCoordinates() {
        List<ActionableFinding> sorted = ActionableFindingOrder.sorted(List.of(
                finding("HIGH", 8.1, "FAKE-CVE-0000-0001", "com.example.fake:zeta:1.0.0"),
                finding("HIGH", 8.1, "FAKE-CVE-0000-0001", "com.example.fake:alpha:1.0.0"),
                finding("HIGH", 8.1, "FAKE-CVE-0000-0001", "com.example.fake:mid:1.0.0")));

        assertEquals(List.of("com.example.fake:alpha:1.0.0", "com.example.fake:mid:1.0.0",
                        "com.example.fake:zeta:1.0.0"),
                sorted.stream().map(f -> f.library().coordinates()).toList());
    }

    @Test
    @DisplayName("a null library sorts after a finding with coordinates")
    void nullLibraryLast() {
        List<ActionableFinding> sorted = ActionableFindingOrder.sorted(List.of(
                finding("HIGH", 8.1, "FAKE-CVE-0000-0001", null),
                finding("HIGH", 8.1, "FAKE-CVE-0000-0001", "com.example.fake:lib:1.0.0")));

        assertTrue(sorted.get(0).library() != null);
        assertTrue(sorted.get(1).library() == null);
    }

    @Test
    @DisplayName("a library present but without coordinates sorts last")
    void libraryWithoutCoordinatesLast() {
        ActionableFinding noCoordinates = new ActionableFinding("FAKE-CVE-0000-0001", null, "HIGH",
                null, null, 8.1, null, null, null, null, null, null, null, null,
                new AffectedLibrary("g", "a", null, null, null, null, null, null, null, null, null,
                        null),
                null, null);

        List<ActionableFinding> sorted = ActionableFindingOrder.sorted(List.of(
                noCoordinates,
                finding("HIGH", 8.1, "FAKE-CVE-0000-0001", "com.example.fake:lib:1.0.0")));

        assertEquals("com.example.fake:lib:1.0.0", sorted.get(0).library().coordinates());
        assertEquals(null, sorted.get(1).library().coordinates());
    }

    // ---------- full ordering ----------

    @Test
    @DisplayName("a fully mixed list produces one exact expected sequence")
    void fullMixedListOrder() {
        List<ActionableFinding> sorted = ActionableFindingOrder.sorted(List.of(
                finding("HIGH", 7.5, "FAKE-H2"),
                finding("HIGH", null, "FAKE-H4"),
                finding("CRITICAL", 9.1, "FAKE-C2"),
                finding("HIGH", 8.8, "FAKE-H1"),
                finding("CRITICAL", 9.9, "FAKE-C1"),
                finding("HIGH", 7.5, "FAKE-H3")));

        assertEquals(List.of(
                        "FAKE-C1",  // CRITICAL 9.9
                        "FAKE-C2",  // CRITICAL 9.1
                        "FAKE-H1",  // HIGH 8.8
                        "FAKE-H2",  // HIGH 7.5, id before H3
                        "FAKE-H3",  // HIGH 7.5
                        "FAKE-H4"), // HIGH, no score
                idsOf(sorted));
    }

    // ---------- determinism ----------

    @Test
    @DisplayName("sorting is idempotent")
    void sortingIsIdempotent() {
        List<ActionableFinding> input = List.of(
                finding("HIGH", 7.5, "FAKE-B"),
                finding("CRITICAL", 9.9, "FAKE-A"),
                finding("HIGH", null, "FAKE-C"));

        List<ActionableFinding> once = ActionableFindingOrder.sorted(input);
        List<ActionableFinding> twice = ActionableFindingOrder.sorted(once);

        assertEquals(idsOf(once), idsOf(twice));
        assertEquals(once, twice);
    }

    @Test
    @DisplayName("identical findings are kept, not collapsed, and keep their relative order")
    void identicalFindingsRetained() {
        ActionableFinding first = finding("HIGH", 8.1, "FAKE-DUP");
        ActionableFinding second = finding("HIGH", 8.1, "FAKE-DUP");

        List<ActionableFinding> sorted = ActionableFindingOrder.sorted(List.of(first, second));

        assertEquals(2, sorted.size(), "a stable sort must not drop a tied duplicate");
        assertEquals(List.of("FAKE-DUP", "FAKE-DUP"), idsOf(sorted));
    }

    @Test
    @DisplayName("the comparator reports ties as equal so ordering stays stable")
    void comparatorReportsTiesAsEqual() {
        ActionableFinding a = finding("HIGH", 8.1, "FAKE-SAME", "com.example.fake:lib:1.0.0");
        ActionableFinding b = finding("HIGH", 8.1, "FAKE-SAME", "com.example.fake:lib:1.0.0");

        assertEquals(0, ActionableFindingOrder.comparator().compare(a, b));
    }

    // ---------- input and result contract ----------

    @Test
    @DisplayName("the input list is left untouched")
    void inputNotMutated() {
        List<ActionableFinding> input = new ArrayList<>(List.of(
                finding("HIGH", 1.0, "FAKE-SECOND"),
                finding("CRITICAL", 9.0, "FAKE-FIRST")));

        ActionableFindingOrder.sorted(input);

        assertEquals(List.of("FAKE-SECOND", "FAKE-FIRST"), idsOf(input),
                "sorted() must not reorder the caller's list");
    }

    @Test
    @DisplayName("the sorted result is immutable")
    void resultIsImmutable() {
        List<ActionableFinding> sorted =
                ActionableFindingOrder.sorted(List.of(finding("HIGH", 1.0, "FAKE-A")));

        assertThrows(UnsupportedOperationException.class,
                () -> sorted.add(finding("HIGH", 2.0, "FAKE-B")));
    }

    @Test
    @DisplayName("a null or empty input yields an empty result")
    void nullOrEmptyInput() {
        assertTrue(ActionableFindingOrder.sorted(null).isEmpty());
        assertTrue(ActionableFindingOrder.sorted(List.of()).isEmpty());
    }
}
