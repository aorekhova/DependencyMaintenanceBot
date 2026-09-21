package com.tungsten.depbot.assessment;

/**
 * How much implementation work the Vulnerability Analysis Engineer expects the Remediation Engineer to
 * need for one remediation group -- deliberately independent of {@link AutomationSafety}: that field asks
 * whether the <em>result</em> may be trusted to automation; this one asks how much <em>work</em> getting
 * there is expected to take. A group can be {@code AUTOMATIC_ALLOWED} and {@code EXTENDED} at once (a
 * large but well-understood migration a person never needs to review), or {@code HUMAN_REVIEW_REQUIRED}
 * and {@code STANDARD} (a small change that still needs a person's judgement for an unrelated reason).
 */
public enum ImplementationBudget {

    /** An ordinary version/property bump, a small BOM or dependencyManagement update, an exclusion, or a
     *  small Maven metadata fix -- no application/source migration expected. */
    STANDARD,

    /**
     * A real migration: crossing a major framework/API boundary, expected Java/source compatibility
     * edits, configuration/XML/plugin changes, a coordinate/package migration, several parts of the
     * repository needing to change together, or a plan that explicitly includes compatibility adaptation.
     */
    EXTENDED
}
