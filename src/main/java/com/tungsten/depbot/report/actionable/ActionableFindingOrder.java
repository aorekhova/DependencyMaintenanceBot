package com.tungsten.depbot.report.actionable;

import com.tungsten.depbot.report.Severity;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * The order findings appear in within the detailed report.
 *
 * <p>The report is written to a fixed filename that automation will read and diff, so the ordering
 * has to be a <em>total</em> order: two runs over the same data must produce the same sequence, or
 * every run would look like a change.
 *
 * <p>Levels, in order of precedence:
 * <ol>
 *   <li>severity — CRITICAL before HIGH</li>
 *   <li>CVSS 3 score, descending — the most severe first</li>
 *   <li>vulnerability id, ascending</li>
 *   <li>library coordinates, ascending</li>
 * </ol>
 *
 * <p>Missing values sort last at every level, so a finding without a score never displaces one that
 * has a high score.
 *
 * <p>Non-finite scores are treated as missing. This matters more than it looks: Java orders
 * {@code NaN} as greater than every real number, so without this guard a finding whose score failed
 * to parse would be promoted to the very top of the report — the most prominent position, given to
 * the least trustworthy data. The mapper already rejects non-finite values; guarding here as well
 * keeps the ordering correct independently of it.
 */
public final class ActionableFindingOrder {

    private static final Comparator<Double> SCORE_DESCENDING_NULLS_LAST =
            Comparator.nullsLast(Comparator.reverseOrder());

    private static final Comparator<String> TEXT_ASCENDING_NULLS_LAST =
            Comparator.nullsLast(Comparator.naturalOrder());

    private static final Comparator<ActionableFinding> COMPARATOR =
            Comparator.<ActionableFinding>comparingInt(ActionableFindingOrder::severityRank)
                    .thenComparing(ActionableFindingOrder::comparableScore,
                            SCORE_DESCENDING_NULLS_LAST)
                    .thenComparing(ActionableFinding::vulnerabilityId,
                            TEXT_ASCENDING_NULLS_LAST)
                    .thenComparing(ActionableFindingOrder::coordinates,
                            TEXT_ASCENDING_NULLS_LAST);

    private ActionableFindingOrder() {
    }

    /**
     * The report ordering. Findings passed to it must not be {@code null}; the report model already
     * guarantees that by rejecting null elements.
     */
    public static Comparator<ActionableFinding> comparator() {
        return COMPARATOR;
    }

    /**
     * Returns a sorted immutable copy, leaving the input untouched.
     *
     * <p>The underlying sort is stable, so findings that tie on all four levels — which duplicates
     * from Mend will — keep their original relative order instead of being shuffled arbitrarily.
     */
    public static List<ActionableFinding> sorted(List<ActionableFinding> findings) {
        if (findings == null || findings.isEmpty()) {
            return List.of();
        }
        List<ActionableFinding> ordered = new ArrayList<>(findings);
        ordered.sort(COMPARATOR);
        return List.copyOf(ordered);
    }

    private static int severityRank(ActionableFinding finding) {
        return Severity.fromRaw(finding.severity()).ordinal();
    }

    /** The score to sort by, or {@code null} when it is absent or not a finite number. */
    private static Double comparableScore(ActionableFinding finding) {
        Double score = finding.cvss3ScoreNumeric();
        if (score == null || !Double.isFinite(score)) {
            return null;
        }
        return score;
    }

    private static String coordinates(ActionableFinding finding) {
        AffectedLibrary library = finding.library();
        return library == null ? null : library.coordinates();
    }
}
