package com.tungsten.depbot.report;

import com.tungsten.depbot.mend.model.VulnerabilityRecord;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.parallel.Resources;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SeverityCountsTest {

    private static List<VulnerabilityRecord> of(String... severities) {
        List<VulnerabilityRecord> list = new ArrayList<>();
        for (String severity : severities) {
            list.add(new VulnerabilityRecord(severity));
        }
        return list;
    }

    @Test
    @DisplayName("mixed severities produce exact per-bucket counts")
    void mixedSeverities() {
        SeverityCounts counts = SeverityCounts.from(
                of("critical", "high", "high", "medium", "low", "low", "low"));

        assertEquals(7, counts.total());
        assertEquals(1, counts.criticalCount());
        assertEquals(2, counts.highCount());
        assertEquals(1, counts.mediumCount());
        assertEquals(3, counts.lowCount());
        assertEquals(0, counts.otherCount());
    }

    @Test
    @DisplayName("empty list yields all zeros and no vulnerabilities")
    void emptyList() {
        SeverityCounts counts = SeverityCounts.from(List.of());
        assertEquals(0, counts.total());
        assertEquals(0, counts.otherCount());
        assertEquals(false, counts.hasVulnerabilities());
    }

    @Test
    @DisplayName("severity matching is case-insensitive")
    void caseInsensitive() {
        SeverityCounts counts = SeverityCounts.from(of("high", "High", "HIGH", "HiGh"));
        assertEquals(4, counts.highCount());
        assertEquals(0, counts.otherCount());
    }

    @Test
    @DisplayName("critical is counted in its own bucket, not folded into high")
    void criticalIsSeparate() {
        SeverityCounts counts = SeverityCounts.from(of("CRITICAL", "critical", "high"));
        assertEquals(2, counts.criticalCount());
        assertEquals(1, counts.highCount());
    }

    @Test
    @DisplayName("surrounding whitespace is ignored")
    void whitespaceIsStripped() {
        SeverityCounts counts = SeverityCounts.from(of("  high  ", "\tlow\n"));
        assertEquals(1, counts.highCount());
        assertEquals(1, counts.lowCount());
        assertEquals(0, counts.otherCount());
    }

    @Test
    @DisplayName("null severity counts as other and is never dropped")
    void nullSeverityCountsAsOther() {
        SeverityCounts counts = SeverityCounts.from(of("high", null));
        assertEquals(2, counts.total());
        assertEquals(1, counts.highCount());
        assertEquals(1, counts.otherCount());
    }

    @Test
    @DisplayName("blank severity counts as other")
    void blankSeverityCountsAsOther() {
        SeverityCounts counts = SeverityCounts.from(of("", "   "));
        assertEquals(2, counts.total());
        assertEquals(2, counts.otherCount());
    }

    @Test
    @DisplayName("unrecognised severity counts as other")
    void unknownSeverityCountsAsOther() {
        SeverityCounts counts = SeverityCounts.from(of("informational", "moderate", "5"));
        assertEquals(3, counts.total());
        assertEquals(3, counts.otherCount());
    }

    @Test
    @DisplayName("a null list does not throw")
    void nullListIsSafe() {
        SeverityCounts counts = assertDoesNotThrow(() -> SeverityCounts.from(null));
        assertEquals(0, counts.total());
    }

    @Test
    @DisplayName("a null element does not throw and is ignored entirely, not counted as other")
    void nullElementIsSafe() {
        // A null list element is not a vulnerability at all -- Mend's array containing a JSON
        // null -- so it must not inflate total or otherCount. This differs from a real record
        // whose severity happens to be null, which is still counted (see nullSeverityCountsAsOther).
        List<VulnerabilityRecord> list = new ArrayList<>(Arrays.asList(
                new VulnerabilityRecord("high"), null));

        SeverityCounts counts = assertDoesNotThrow(() -> SeverityCounts.from(list));
        assertEquals(1, counts.total());
        assertEquals(1, counts.highCount());
        assertEquals(0, counts.otherCount());
    }

    @Test
    @DisplayName("total always equals list size and the sum of every bucket")
    void invariantHolds() {
        List<VulnerabilityRecord> list =
                of("critical", "high", "medium", "low", "informational", null, "  ", "HIGH");

        SeverityCounts counts = SeverityCounts.from(list);

        assertEquals(list.size(), counts.total(), "total must equal the number of entries");
        assertEquals(counts.total(),
                counts.criticalCount() + counts.highCount() + counts.mediumCount()
                        + counts.lowCount() + counts.otherCount(),
                "buckets must sum to the total");
    }

    @Test
    @DisplayName("counting is unaffected by a Turkish default locale")
    @ResourceLock(Resources.LOCALE)
    void turkishLocaleRegression() {
        Locale original = Locale.getDefault();
        try {
            // Under tr, "HIGH".toLowerCase() yields a dotless i and would not match "high".
            Locale.setDefault(Locale.forLanguageTag("tr"));
            SeverityCounts counts = SeverityCounts.from(of("HIGH", "HIGH", "LOW"));
            assertEquals(2, counts.highCount());
            assertEquals(1, counts.lowCount());
            assertEquals(0, counts.otherCount());
        } finally {
            Locale.setDefault(original);
        }
    }
}
