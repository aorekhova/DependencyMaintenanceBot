package com.tungsten.depbot.assessment;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.List;

/**
 * How big the change the assessment is proposing actually is, on a fixed 1-to-10 scale.
 *
 * <p>This measures size and nothing else -- whether the change is safe to trust to automation is a
 * separate question, answered by {@link AutomationSafety}, and deliberately not derivable from this
 * score. A patch-level bump can still need a human's review, and an architectural migration can still
 * be judged safe to automate; conflating the two was the exact coupling this type used to encode and no
 * longer does.
 *
 * <p>{@link #SCALE} is defined once, here, and nowhere else: it is what the assessment prompt prints
 * for Claude to score against.
 *
 * <p>Serialises as a plain integer, so the assessment document reads {@code "impactScore": 3} rather
 * than a wrapper object.
 */
public record ImpactScore(int value) {

    public static final int MINIMUM = 1;
    public static final int MAXIMUM = 10;

    /**
     * What each score means, indexed by the score itself ({@code SCALE.get(1)} describes a 1).
     * Element {@code 0} is unused and blank, so the list can be indexed by score directly rather
     * than through an off-by-one adjustment at every use.
     */
    public static final List<String> SCALE = List.of(
            "",
            "a single trivial version or property change",
            "a small patch-level dependency update",
            "a dependency family or BOM move, plus generated metadata",
            "several build or configuration changes",
            "small Java compatibility changes",
            "moderate source and test changes",
            "a substantial but bounded multi-file or multi-module change",
            "a large but well-understood and localised remediation",
            "an architectural migration, or a very broad change",
            "effectively a separate migration project");

    public ImpactScore {
        if (value < MINIMUM || value > MAXIMUM) {
            throw new IllegalArgumentException(
                    "impactScore must be between " + MINIMUM + " and " + MAXIMUM + ", but was: " + value);
        }
    }

    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public static ImpactScore of(int value) {
        return new ImpactScore(value);
    }

    @JsonValue
    public int value() {
        return value;
    }

    public String description() {
        return SCALE.get(value);
    }

    /** The whole scale as numbered lines, for the assessment prompt to present verbatim. */
    public static String scaleAsLines() {
        StringBuilder lines = new StringBuilder();
        for (int score = MINIMUM; score <= MAXIMUM; score++) {
            lines.append(score).append(" - ").append(SCALE.get(score));
            if (score < MAXIMUM) {
                lines.append('\n');
            }
        }
        return lines.toString();
    }
}
