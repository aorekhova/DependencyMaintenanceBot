package com.tungsten.depbot.assessment;

/**
 * How safe it is to trust this remediation to automation, decided independently of {@link ImpactScore}.
 *
 * <p>{@code ImpactScore} measures how large a change is; this measures whether the bot should be the
 * one to carry it out and commit it unattended. The two answer genuinely different questions. A small,
 * one-line version bump can still be {@link #HUMAN_REVIEW_REQUIRED} if it sits inside a coordinated,
 * runtime-sensitive dependency family with a proven binary-compatibility risk; a large, multi-file
 * change can still be {@link #AUTOMATIC_ALLOWED} if the assessment found a clean, well-validated path
 * through it. Neither value may be derived mechanically from the score -- it is its own engineering
 * judgment.
 */
public enum AutomationSafety {

    /** The bot runs the Remediation Engineer, every gate, and a local commit; fully automated. */
    AUTOMATIC_ALLOWED,

    /**
     * No implementation call runs at all. Instead, a read-only Human Review Engineer writes up a report
     * on this group for a person to act on -- what is vulnerable, why, what this analysis already
     * established, what would fix it, and how to validate it. The bot changes nothing here.
     *
     * <p>Distinct from {@link RemediationVerdict#MANUAL_REMEDIATION_REQUIRED}: this means a safe,
     * reviewable plan exists, it is simply not authorised to run unattended -- not that no plan could be
     * established at all.
     */
    HUMAN_REVIEW_REQUIRED,

    /**
     * Legacy value only. The Vulnerability Analysis Engineer never assigns this any more -- it is kept
     * solely so a previously persisted {@code analysis.json} that still has it can be read without
     * failing. A group carrying this value is treated exactly like {@link #HUMAN_REVIEW_REQUIRED}
     * everywhere it is consulted.
     */
    AUTOMATION_BLOCKED
}
