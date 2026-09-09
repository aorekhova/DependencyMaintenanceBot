package com.tungsten.depbot.assessment;

/**
 * What kind of dependency edit one {@link PlannedDependencyChange} describes -- deliberately narrow, so
 * a later {@code PlanConformanceGate} can state, per value, exactly what it is able to prove about the
 * actual diff rather than one generic "does the diff roughly match" check.
 */
public enum PlannedChangeType {

    /** Raising a dependency's own effective version, however that version is actually expressed. */
    VERSION_BUMP,

    /** Adding or changing a {@code <dependencyManagement>} (or imported BOM) entry. */
    DEPENDENCY_MANAGEMENT_ADDITION,

    /** Adding a transitive-dependency exclusion. */
    EXCLUSION_ADDED,

    /**
     * Anything else. Deliberately the weakest option: a gate can only ever confirm this change's file
     * scope, never its semantics, so the analysis should prefer a more specific value whenever one fits.
     */
    OTHER
}
