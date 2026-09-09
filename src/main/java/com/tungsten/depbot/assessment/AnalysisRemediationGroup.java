package com.tungsten.depbot.assessment;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * A remediation group as the Vulnerability Analysis Engineer itself determined it -- which findings,
 * and which companion dependencies with no finding of their own, must be remediated together, and
 * whether that combined change may be trusted to automation.
 *
 * <p>This is the whole of what used to be spread across every {@code REMEDIATION_REQUIRED}
 * {@code DeveloperAssessment}: {@code impactScore}, {@code automationSafety}, {@code sourceRef}, the
 * plans. Under the batch model those all belong to the group, not to any one finding, because
 * remediation is now carried out and committed per group, never per finding.
 *
 * <p>{@code groupId} is chosen by Claude and must be unique within the batch; {@code memberCoordinates}
 * must exactly match the set of {@link FindingAssessment}s whose {@code remediationGroupId} names this
 * group -- {@link com.tungsten.depbot.remediation.RemediationGroupValidator} checks this both ways,
 * rather than the bot inferring membership itself the way {@code RemediationGroupBuilder}'s union-find
 * used to.
 *
 * <p>{@code claimedSourceCommitSha} is never used to create a branch, for the same reason it never was
 * on the old per-finding assessment: the orchestrator resolves {@code sourceRef} through git itself.
 */
public record AnalysisRemediationGroup(
        String groupId,
        List<String> memberCoordinates,
        List<String> companionCoordinates,
        String groupingReason,
        String sourceRef,
        @JsonProperty("sourceCommitSha") String claimedSourceCommitSha,
        DependencyOrigin origin,
        String dependencyRelationship,
        String observedVersion,
        String recommendedRemediation,
        String recommendedTargetVersion,
        List<String> affectedFiles,
        ImpactScore impactScore,
        String impactReason,
        AutomationSafety automationSafety,
        String automationSafetyReason,
        List<String> implementationPlan,
        List<String> validationPlan,
        List<PlannedDependencyChange> plannedChanges) {

    public AnalysisRemediationGroup {
        memberCoordinates = immutable(memberCoordinates);
        companionCoordinates = immutable(companionCoordinates);
        affectedFiles = immutable(affectedFiles);
        implementationPlan = immutable(implementationPlan);
        validationPlan = immutable(validationPlan);
        plannedChanges = immutablePlannedChanges(plannedChanges);
    }

    public boolean hasImpactScore() {
        return impactScore != null;
    }

    public boolean hasAutomationSafety() {
        return automationSafety != null;
    }

    /** Whether a ref was identified at all -- without one there is nothing to branch from. */
    public boolean hasSourceRef() {
        return sourceRef != null && !sourceRef.isBlank();
    }

    /**
     * Whether the Vulnerability Analysis Engineer established any remediation direction at all for this
     * group -- narrative plan content, machine-readable planned changes, or both. Deliberately independent
     * of {@code sourceRef} or {@code recommendedTargetVersion}: this asks only "is there plan content",
     * not whether that content could actually be carried out.
     */
    public boolean hasEstablishedRemediationDirection() {
        return !implementationPlan.isEmpty() || !plannedChanges.isEmpty();
    }

    /**
     * Whether this group must be routed to the risky, isolated singleton path rather than an ordinary
     * cohort branch -- decided before any candidate branch is cut and before Implementation ever runs, so
     * an ordinary candidate commit is never created for a group that turns out to need isolation.
     */
    public boolean requiresRiskyRouting() {
        if (!hasAutomationSafety()) {
            return true;
        }
        if (automationSafety != AutomationSafety.AUTOMATIC_ALLOWED) {
            return true;
        }
        if (plannedChanges.stream().anyMatch(change -> change.changeType() == PlannedChangeType.OTHER)) {
            return true;
        }
        return plannedChanges.isEmpty();
    }

    /**
     * Why this group needed risky, isolated routing, in a form suitable for a report -- {@code null} when
     * {@link #requiresRiskyRouting()} is {@code false}.
     */
    public String effectiveRiskReason() {
        if (!hasAutomationSafety()) {
            return "Vulnerability Analysis did not fully establish automation-safety/impact "
                    + "classification for this group (best-effort/partial recovery) -- treated as "
                    + "human-review-required since Java cannot independently confirm it is safe to run "
                    + "unattended.";
        }
        if (automationSafety == AutomationSafety.AUTOMATION_BLOCKED) {
            return "Originally classified AUTOMATION_BLOCKED (legacy) by analysis; treated identically "
                    + "to HUMAN_REVIEW_REQUIRED for automation purposes.";
        }
        if (automationSafety == AutomationSafety.HUMAN_REVIEW_REQUIRED) {
            return "Classified HUMAN_REVIEW_REQUIRED by Vulnerability Analysis: " + automationSafetyReason;
        }
        if (plannedChanges.stream().anyMatch(change -> change.changeType() == PlannedChangeType.OTHER)) {
            return "Originally classified AUTOMATIC_ALLOWED by analysis; Java routing escalated this "
                    + "remediation to human-review-required because the plan contains machine-unverifiable "
                    + "OTHER changes.";
        }
        if (plannedChanges.isEmpty()) {
            return "Originally classified AUTOMATIC_ALLOWED by analysis, but the machine-readable "
                    + "plannedChanges needed for objective verification is missing (legacy/partial-analysis "
                    + "data) -- escalated to human-review-required.";
        }
        return null;
    }

    private static List<String> immutable(List<String> values) {
        return values == null ? List.of() : List.copyOf(values);
    }

    private static List<PlannedDependencyChange> immutablePlannedChanges(List<PlannedDependencyChange> values) {
        return values == null ? List.of() : List.copyOf(values);
    }
}
