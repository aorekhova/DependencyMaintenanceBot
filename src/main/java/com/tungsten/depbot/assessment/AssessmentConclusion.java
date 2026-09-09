package com.tungsten.depbot.assessment;

import com.fasterxml.jackson.annotation.JsonCreator;

import java.util.Locale;

/**
 * What the assessment concluded the situation actually is.
 *
 * <p>This is Claude's finding, not a decision about what the bot will do. Whether an implementation
 * actually runs is {@link ImpactScorePolicy}'s call, taken from this together with the impact score
 * -- see {@link RemediationVerdict}. Keeping the two apart is what stops an assessment from being
 * able to authorise its own execution.
 */
public enum AssessmentConclusion {

    /**
     * The dependency is genuinely present on some ref and needs changing. The assessment must then
     * also carry an impact score, the ref its evidence points at, and both plans.
     */
    REMEDIATION_REQUIRED,

    /**
     * The finding does not apply to this repository as it stands -- the artifact is absent from every
     * ref examined, or is already at or past a fixed version. This is a real, useful answer, not a
     * failure: it is exactly what the jackson-databind pilot should have been able to report.
     */
    NO_ACTION_REQUIRED,

    /**
     * The assessment could not establish the facts it needed. Treated as needing a human, never as
     * permission to proceed on a guess.
     */
    INCONCLUSIVE;

    /**
     * Tolerant of case, surrounding whitespace, hyphens and spaces, since this arrives as free text
     * from a model. An unrecognised value is rejected rather than mapped to a default: silently
     * reading an unknown conclusion as one of these three would be inventing a finding.
     */
    @JsonCreator
    public static AssessmentConclusion from(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("conclusion is missing");
        }
        String normalized = raw.strip().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
        for (AssessmentConclusion conclusion : values()) {
            if (conclusion.name().equals(normalized)) {
                return conclusion;
            }
        }
        throw new IllegalArgumentException("unrecognised conclusion: " + raw.strip());
    }
}
