package com.tungsten.depbot.assessment;

import java.util.Objects;

/**
 * The one place that decides whether a remediation group leads to an automatic implementation.
 *
 * <p>Under the batch analysis model, {@code impactScore}/{@code automationSafety}/{@code sourceRef} are
 * all properties of an {@link AnalysisRemediationGroup}, not of any one finding -- a group is what gets
 * implemented and committed, so it is the group's automation-safety decision that governs. The decision
 * is still driven by {@link AutomationSafety}, never by {@link ImpactScore}: the score is only ever a
 * size. {@link AutomationSafety#AUTOMATIC_ALLOWED} becomes {@link RemediationVerdict#AUTOMATIC_ALLOWED};
 * {@link AutomationSafety#HUMAN_REVIEW_REQUIRED} and {@link AutomationSafety#AUTOMATION_BLOCKED} both
 * become verdicts that route the group to the read-only Human Review Engineer instead of the
 * Remediation Engineer -- {@link RemediationVerdict#HUMAN_REVIEW_REQUIRED} and
 * {@link RemediationVerdict#MANUAL_REMEDIATION_REQUIRED} respectively, so a report can still distinguish
 * "safe plan, withheld from automation" from "no safe plan established."
 *
 * <p><strong>Every uncertain path fails closed.</strong> A group with no score, no automation-safety
 * decision, or no source ref to branch from all produce {@code MANUAL_REMEDIATION_REQUIRED}. The
 * alternative -- defaulting to "proceed" when the input is not understood -- would let a malformed
 * answer authorise unattended edits to a real repository, which is precisely the outcome this policy
 * exists to prevent.
 */
public final class ImpactScorePolicy {

    private ImpactScorePolicy() {
    }

    /** The decision for one remediation group Claude's analysis determined. */
    public static RemediationDecision decide(AnalysisRemediationGroup group) {
        Objects.requireNonNull(group, "group");

        if (!group.hasImpactScore()) {
            return new RemediationDecision(
                    RemediationVerdict.MANUAL_REMEDIATION_REQUIRED,
                    "The remediation group gave no impact score, so the size of the change is unknown and "
                            + "it was not attempted automatically.");
        }
        if (!group.hasAutomationSafety()) {
            return new RemediationDecision(
                    RemediationVerdict.MANUAL_REMEDIATION_REQUIRED,
                    "The remediation group gave no automation-safety decision, so whether it may be trusted "
                            + "to automation is unknown.");
        }
        if (!group.hasSourceRef()) {
            // The group is kept and reported; it simply cannot be acted on unattended, because there is
            // no ref for a remediation branch to be created from.
            return new RemediationDecision(
                    RemediationVerdict.MANUAL_REMEDIATION_REQUIRED,
                    "The remediation group identified no source ref, so there is nothing to create a "
                            + "remediation branch from.");
        }

        String safetyReason = group.automationSafetyReason();
        return switch (group.automationSafety()) {
            case AUTOMATIC_ALLOWED -> new RemediationDecision(
                    RemediationVerdict.AUTOMATIC_ALLOWED,
                    "Automation safety AUTOMATIC_ALLOWED: " + safetyReason);
            case HUMAN_REVIEW_REQUIRED -> new RemediationDecision(
                    RemediationVerdict.HUMAN_REVIEW_REQUIRED,
                    "Automation safety HUMAN_REVIEW_REQUIRED: " + safetyReason);
            case AUTOMATION_BLOCKED -> new RemediationDecision(
                    RemediationVerdict.MANUAL_REMEDIATION_REQUIRED,
                    "Automation safety AUTOMATION_BLOCKED: " + safetyReason);
        };
    }

    /** The decision for a finding whose conclusion was {@code INCONCLUSIVE}, or that named no group. */
    public static RemediationDecision inconclusive() {
        return new RemediationDecision(
                RemediationVerdict.MANUAL_REMEDIATION_REQUIRED,
                "The analysis could not establish the facts it needed, so nothing was changed "
                        + "automatically.");
    }

    /** The decision for a finding whose conclusion was {@code NO_ACTION_REQUIRED}. */
    public static RemediationDecision noActionRequired() {
        return new RemediationDecision(
                RemediationVerdict.NO_ACTION_REQUIRED,
                "The analysis found nothing to remediate in this repository.");
    }

    /**
     * The decision for a finding or a whole batch that could not be read or validated at all.
     *
     * @param safeReason why it could not be read -- a structural description, never the unparsed
     *                   answer itself, which came from inside a real product repository
     */
    public static RemediationDecision failClosed(String safeReason) {
        Objects.requireNonNull(safeReason, "safeReason");
        return new RemediationDecision(
                RemediationVerdict.MANUAL_REMEDIATION_REQUIRED,
                "The analysis could not be used, so nothing was changed automatically: " + safeReason);
    }
}
