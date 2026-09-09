package com.tungsten.depbot.implementation;

import java.util.List;

/**
 * What the implementation developer did, and what they found when they got there.
 *
 * <p>{@code observedState} is required whatever the conclusion, and it is the field that makes the
 * safe-stop contract real. The implementation runs on a branch chosen from an assessment's reading of a
 * <em>different</em> checkout state, and the assessment can be wrong -- so the first thing this report
 * has to answer is what is actually there, in its own words, rather than restating the assessment back.
 *
 * <p>{@code divergenceFromAssessment} may be non-empty on a {@link ImplementationConclusion#COMPLETED}
 * report too. Finding that the assessment was partly wrong and remediating correctly anyway is a good
 * outcome, and worth recording; it is only when the divergence undermines the remediation itself that
 * stopping is the right answer.
 *
 * <p>Nothing here constrains what was changed. A remediation may legitimately have touched build
 * configuration, a BOM or version property, Java sources, tests, resources, generated metadata or a
 * related dependency in the same family -- {@code changesMade} records what was done, it does not have
 * to justify itself against a list of permitted file kinds.
 */
public record ImplementationReport(
        String schemaVersion,
        String coordinates,
        ImplementationConclusion conclusion,
        String summary,
        String observedState,
        List<String> changesMade,
        List<String> divergenceFromAssessment,
        List<String> validationPerformed,
        List<String> remainingWork,
        List<String> risks) {

    /** The schema generation this application understands. */
    public static final String CURRENT_SCHEMA_VERSION = "1.0";

    public ImplementationReport {
        schemaVersion = (schemaVersion == null || schemaVersion.isBlank())
                ? CURRENT_SCHEMA_VERSION
                : schemaVersion.strip();
        changesMade = immutable(changesMade);
        divergenceFromAssessment = immutable(divergenceFromAssessment);
        validationPerformed = immutable(validationPerformed);
        remainingWork = immutable(remainingWork);
        risks = immutable(risks);
    }

    /** Whether the orchestrator may keep the working tree. False for either kind of stop. */
    public boolean workCompleted() {
        return conclusion != null && conclusion.workCompleted();
    }

    private static List<String> immutable(List<String> values) {
        return values == null ? List.of() : List.copyOf(values);
    }
}
