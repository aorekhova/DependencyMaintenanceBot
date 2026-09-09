package com.tungsten.depbot.report;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.parallel.Resources;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SeverityTest {

    @Test
    @DisplayName("each known severity maps to its own value")
    void knownSeverities() {
        assertEquals(Severity.CRITICAL, Severity.fromRaw("critical"));
        assertEquals(Severity.HIGH, Severity.fromRaw("high"));
        assertEquals(Severity.MEDIUM, Severity.fromRaw("medium"));
        assertEquals(Severity.LOW, Severity.fromRaw("low"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"high", "High", "HIGH", "hIgH"})
    @DisplayName("matching is case-insensitive")
    void caseInsensitive(String raw) {
        assertEquals(Severity.HIGH, Severity.fromRaw(raw));
    }

    @Test
    @DisplayName("surrounding whitespace is ignored")
    void whitespaceIsStripped() {
        assertEquals(Severity.CRITICAL, Severity.fromRaw("  critical  "));
        assertEquals(Severity.LOW, Severity.fromRaw("\tlow\n"));
    }

    @Test
    @DisplayName("null becomes OTHER rather than throwing")
    void nullBecomesOther() {
        assertEquals(Severity.OTHER, Severity.fromRaw(null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\t", "informational", "moderate", "5", "none"})
    @DisplayName("blank and unrecognised values become OTHER")
    void unrecognisedBecomesOther(String raw) {
        assertEquals(Severity.OTHER, Severity.fromRaw(raw));
    }

    @Test
    @DisplayName("only CRITICAL and HIGH are actionable")
    void actionableSeverities() {
        assertTrue(Severity.CRITICAL.isActionable());
        assertTrue(Severity.HIGH.isActionable());
        assertFalse(Severity.MEDIUM.isActionable());
        assertFalse(Severity.LOW.isActionable());
        assertFalse(Severity.OTHER.isActionable());
    }

    @Test
    @DisplayName("declaration order puts CRITICAL before HIGH for report sorting")
    void declarationOrderDefinesSortPrecedence() {
        assertTrue(Severity.CRITICAL.ordinal() < Severity.HIGH.ordinal());
        assertTrue(Severity.HIGH.ordinal() < Severity.MEDIUM.ordinal());
        assertTrue(Severity.MEDIUM.ordinal() < Severity.LOW.ordinal());
        assertTrue(Severity.LOW.ordinal() < Severity.OTHER.ordinal());
    }

    @Test
    @DisplayName("classification is unaffected by a Turkish default locale")
    @ResourceLock(Resources.LOCALE)
    void turkishLocaleRegression() {
        Locale original = Locale.getDefault();
        try {
            // Under tr, "HIGH".toLowerCase() yields a dotless i and would not match "high".
            Locale.setDefault(Locale.forLanguageTag("tr"));
            assertEquals(Severity.HIGH, Severity.fromRaw("HIGH"));
            assertEquals(Severity.CRITICAL, Severity.fromRaw("CRITICAL"));
        } finally {
            Locale.setDefault(original);
        }
    }

    @Test
    @DisplayName("every enum value is reachable from its own lowercase name")
    void allValuesRoundTripExceptOther() {
        for (Severity severity : Severity.values()) {
            if (severity == Severity.OTHER) {
                continue;
            }
            assertEquals(severity,
                    Severity.fromRaw(severity.name().toLowerCase(Locale.ROOT)),
                    "value not reachable from its own name: " + severity);
        }
    }

    @Test
    @DisplayName("executionPriorityRank() is an explicit ranking, not a stand-in for ordinal()")
    void severityPriorityRankIsExplicitNotOrdinal() {
        // Calls the rank method directly against fixed expected integers for every constant -- unlike
        // merely comparing two severities' relative order, this catches a future accidental reordering
        // of the enum's declaration even in the (dangerous) case where it happened to preserve relative
        // ordinal order for whichever specific pair another test happens to compare.
        assertEquals(0, Severity.CRITICAL.executionPriorityRank());
        assertEquals(1, Severity.HIGH.executionPriorityRank());
        assertEquals(2, Severity.MEDIUM.executionPriorityRank());
        assertEquals(3, Severity.LOW.executionPriorityRank());
        assertEquals(4, Severity.OTHER.executionPriorityRank());
    }
}
