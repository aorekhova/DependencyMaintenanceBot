package com.tungsten.depbot.assessment;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ImpactScoreTest {

    @Test
    @DisplayName("the scale runs from one to ten, and carries no automation ceiling of its own")
    void scaleBoundsAreOneToTen() {
        assertEquals(1, ImpactScore.MINIMUM);
        assertEquals(10, ImpactScore.MAXIMUM);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1, 11, 100, Integer.MIN_VALUE, Integer.MAX_VALUE})
    @DisplayName("a score outside the scale is rejected rather than clamped")
    void outOfRangeIsRejected(int score) {
        assertThrows(IllegalArgumentException.class, () -> new ImpactScore(score));
    }

    @Test
    @DisplayName("every score on the scale has a description, so no score is unexplained")
    void everyScoreHasADescription() {
        for (int score = ImpactScore.MINIMUM; score <= ImpactScore.MAXIMUM; score++) {
            assertFalse(new ImpactScore(score).description().isBlank(), "score " + score);
        }
    }

    @Test
    @DisplayName("the lines the prompt prints cover exactly the declared scale")
    void scaleLinesCoverExactlyTheScale() {
        String[] lines = ImpactScore.scaleAsLines().split("\n");

        assertEquals(ImpactScore.MAXIMUM, lines.length);
        assertTrue(lines[0].startsWith("1 - "), lines[0]);
        assertTrue(lines[lines.length - 1].startsWith("10 - "), lines[lines.length - 1]);
        for (int score = ImpactScore.MINIMUM; score <= ImpactScore.MAXIMUM; score++) {
            assertTrue(lines[score - 1].contains(ImpactScore.SCALE.get(score)), lines[score - 1]);
        }
    }

    @Test
    @DisplayName("the scale is immutable, so nothing can redefine what a score means at runtime")
    void scaleIsImmutable() {
        assertThrows(UnsupportedOperationException.class, () -> ImpactScore.SCALE.set(1, "anything"));
    }
}
