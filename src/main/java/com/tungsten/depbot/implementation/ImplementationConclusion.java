package com.tungsten.depbot.implementation;

import com.fasterxml.jackson.annotation.JsonCreator;

import java.util.Locale;

/**
 * How the implementation ended, as the developer who did the work reports it.
 *
 * <p>Only {@link #COMPLETED} lets the orchestrator keep the change. The other two exist so that
 * stopping is a first-class, reportable outcome rather than something an agent has to disguise as
 * success -- an implementation that discovers the branch does not match the assessment must be able to
 * say exactly that, and be believed, instead of pressing on with a plan whose premise has just been
 * disproved.
 */
public enum ImplementationConclusion {

    /** The remediation was carried through. The change is eligible to be kept, subject to the diff policy. */
    COMPLETED,

    /**
     * The actual state of the branch contradicted the assessment -- the dependency is not where or what
     * the assessment concluded, or the version in front of it is not the one that was assessed -- so the
     * plan was abandoned rather than forced. Any partial edits are undone.
     */
    STOPPED_ASSESSMENT_CONTRADICTED,

    /**
     * The remediation could not be carried out for some other reason: something needed was missing, or
     * the change turned out to require more than this call could safely do. Any partial edits are undone.
     */
    STOPPED_BLOCKED,

    /**
     * The implementation was working from the Vulnerability Analysis Engineer's own established plan
     * (narrative {@code implementationPlan}/{@code validationPlan} and, where present, machine-readable
     * {@code plannedChanges} on the group's {@code AnalysisRemediationGroup}) -- a binding direction, not
     * a suggestion -- and discovered mid-execution that the plan itself is incomplete, wrong, or needs a
     * different strategy than what was established. Rather than improvising a different target version,
     * remediation strategy, or substantive change the plan never authorised, the implementation must stop
     * here and say plainly what is wrong, so the group can go through one bounded repair attempt (the
     * same Remediation Engineer, armed with this failure evidence, still working within the same
     * direction) instead of silently deviating from what Vulnerability Analysis established. Any partial
     * edits are undone.
     */
    STOPPED_PLAN_DEVIATION_REQUIRED;

    /** Tolerant of case, whitespace, hyphens and spaces; an unrecognised value is rejected. */
    @JsonCreator
    public static ImplementationConclusion from(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("conclusion is missing");
        }
        String normalized = raw.strip().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
        for (ImplementationConclusion conclusion : values()) {
            if (conclusion.name().equals(normalized)) {
                return conclusion;
            }
        }
        throw new IllegalArgumentException("unrecognised implementation conclusion: " + raw.strip());
    }

    /** Whether the orchestrator may keep whatever is in the working tree. */
    public boolean workCompleted() {
        return this == COMPLETED;
    }
}
