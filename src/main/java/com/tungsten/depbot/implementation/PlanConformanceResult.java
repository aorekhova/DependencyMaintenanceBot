package com.tungsten.depbot.implementation;

import java.util.List;

/**
 * The Java-owned, structural verdict on whether an implementation's actual diff matches its approved
 * plan's machine-readable {@code plannedChanges} -- see {@link PlanConformanceGate}.
 *
 * <p>This is in addition to, never a substitute for, Implementation's own
 * {@code STOPPED_PLAN_DEVIATION_REQUIRED} self-report -- either signal alone is sufficient to treat an
 * attempt as a plan deviation.
 *
 * <p>{@code unverifiableNotes} is purely informational: a {@code PlannedChangeType.OTHER} entry is, by
 * definition, a kind of change Java cannot objectively verify, so it is recorded here for a human to
 * read, never turned into a {@code violations} entry -- {@code OTHER} alone never makes {@code
 * conformant} {@code false}.
 */
public record PlanConformanceResult(boolean conformant, List<String> violations, List<String> unverifiableNotes) {

    public PlanConformanceResult {
        violations = violations == null ? List.of() : List.copyOf(violations);
        unverifiableNotes = unverifiableNotes == null ? List.of() : List.copyOf(unverifiableNotes);
    }
}
