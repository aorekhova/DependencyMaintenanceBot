package com.tungsten.depbot.remediation;

import com.tungsten.depbot.implementation.ImplementationConclusion;
import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;
import com.tungsten.depbot.validation.ValidationStatus;

import java.util.List;
import java.util.Objects;

/**
 * The bot-assembled, structured record of why an automatic remediation group was rejected -- every
 * field programmatically filled, never Claude's unverified word for a structural fact, the same
 * philosophy as {@link RemediationReport}. Attached to the Human Review context/report only for a group
 * that genuinely attempted automation and was rejected; a group routed to Human Review straight from the
 * analysis (never attempted) never carries one.
 *
 * <p>{@code acceptedBaseSha} is this group's own local starting point (the cumulative tip immediately
 * before it, {@code S_{n-1}}) -- deliberately distinct from any Jenkins call's {@code baselineSha}
 * (always the cohort's original verified SHA, {@code S0}), used here purely for traceability: what this
 * group itself was implemented against.
 */
public record RejectedGroupOutcome(
        String schemaVersion,
        String groupId,
        String priority,
        Integer executionOrder,
        List<String> memberCoordinates,
        String acceptedBaseSha,
        RejectionStage stoppedAtStage,
        String whatWasAttempted,
        List<String> whatChanged,
        ImplementationConclusion implementationConclusion,
        ValidationStatus dependencyValidationStatus,
        ValidationStatus fullBuildValidationStatus,
        JenkinsValidationOutcome cumulativeJenkinsValidation,
        String failureReason,
        boolean rollbackSucceeded,
        String cumulativeStateAfterRejection,
        boolean pipelineContinued,
        List<String> remainingWork,
        List<String> risks,
        DiagnosticClassification diagnosticClassification,
        String applicablePatch,
        String effectiveRiskReason,
        List<String> conformanceViolations) {

    public static final String CURRENT_SCHEMA_VERSION = "1.0";

    public RejectedGroupOutcome {
        schemaVersion = (schemaVersion == null || schemaVersion.isBlank())
                ? CURRENT_SCHEMA_VERSION : schemaVersion.strip();
        Objects.requireNonNull(groupId, "groupId");
        Objects.requireNonNull(stoppedAtStage, "stoppedAtStage");
        Objects.requireNonNull(failureReason, "failureReason");
        memberCoordinates = memberCoordinates == null ? List.of() : List.copyOf(memberCoordinates);
        whatChanged = whatChanged == null ? List.of() : List.copyOf(whatChanged);
        remainingWork = remainingWork == null ? List.of() : List.copyOf(remainingWork);
        risks = risks == null ? List.of() : List.copyOf(risks);
        diagnosticClassification = diagnosticClassification == null
                ? DiagnosticClassification.DIAGNOSTIC_NOT_APPLICABLE : diagnosticClassification;
        conformanceViolations = conformanceViolations == null ? List.of() : List.copyOf(conformanceViolations);
    }

    /**
     * Backward-compatible shape from before {@code effectiveRiskReason}/{@code conformanceViolations}
     * existed -- defaults both to empty/{@code null}. Kept so every existing caller keeps compiling
     * unchanged.
     */
    public RejectedGroupOutcome(
            String schemaVersion,
            String groupId,
            String priority,
            Integer executionOrder,
            List<String> memberCoordinates,
            String acceptedBaseSha,
            RejectionStage stoppedAtStage,
            String whatWasAttempted,
            List<String> whatChanged,
            ImplementationConclusion implementationConclusion,
            ValidationStatus dependencyValidationStatus,
            ValidationStatus fullBuildValidationStatus,
            JenkinsValidationOutcome cumulativeJenkinsValidation,
            String failureReason,
            boolean rollbackSucceeded,
            String cumulativeStateAfterRejection,
            boolean pipelineContinued,
            List<String> remainingWork,
            List<String> risks,
            DiagnosticClassification diagnosticClassification,
            String applicablePatch) {
        this(schemaVersion, groupId, priority, executionOrder, memberCoordinates, acceptedBaseSha,
                stoppedAtStage, whatWasAttempted, whatChanged, implementationConclusion,
                dependencyValidationStatus, fullBuildValidationStatus, cumulativeJenkinsValidation,
                failureReason, rollbackSucceeded, cumulativeStateAfterRejection, pipelineContinued,
                remainingWork, risks, diagnosticClassification, applicablePatch, null, List.of());
    }
}
