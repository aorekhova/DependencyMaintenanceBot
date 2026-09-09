package com.tungsten.depbot.remediation;

import com.tungsten.depbot.assessment.AutomationSafety;
import com.tungsten.depbot.implementation.ImplementationConclusion;
import com.tungsten.depbot.jenkins.JenkinsValidationStatus;
import com.tungsten.depbot.validation.ValidationStatus;

import java.util.List;
import java.util.Objects;

/**
 * The persistent, incrementally-rewritten-in-full audit trail for one group's whole remediation
 * attempt -- {@code group-state.json}, written by {@link GroupStateWriter}. Purely an audit trail: nothing
 * in this codebase reads it back to skip already-completed work. Its shape is nonetheless deliberately
 * resume-friendly for a future feature that might -- an explicit {@link #lastCompletedStage}, monotonic
 * {@code attemptNumber}s on {@link ImplementationAttemptState}, and every artifact reference as a path
 * string rather than duplicated content (matching {@link CohortsIndex.Commit#remediationReportPath}'s own
 * existing precedent).
 */
public record GroupState(
        String schemaVersion,
        String runId,
        String groupId,
        List<String> memberCoordinates,
        String verifiedSourceRef,
        String verifiedSourceSha,
        boolean risky,
        AutomationSafety automationSafety,
        String automationSafetyReason,
        String effectiveRiskReason,
        GroupLifecycleStage lastCompletedStage,
        String updatedAt,
        List<ImplementationAttemptState> implementationAttempts,
        String applicablePatch,
        GroupFinalOutcome finalOutcome,
        GroupPublicationOutcome publicationOutcome) {

    public static final String CURRENT_SCHEMA_VERSION = "1.0";

    public GroupState {
        schemaVersion = (schemaVersion == null || schemaVersion.isBlank())
                ? CURRENT_SCHEMA_VERSION : schemaVersion.strip();
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(groupId, "groupId");
        Objects.requireNonNull(lastCompletedStage, "lastCompletedStage");
        memberCoordinates = memberCoordinates == null ? List.of() : List.copyOf(memberCoordinates);
        implementationAttempts = implementationAttempts == null ? List.of() : List.copyOf(implementationAttempts);
    }

    /** One implementation attempt's own summary -- every path field is a STRING, never embedded content. */
    public record ImplementationAttemptState(
            int attemptNumber,
            String implementationArtifactPath,
            ImplementationConclusion conclusion,
            ValidationStatus dependencyValidationStatus,
            ValidationStatus fullBuildValidationStatus,
            String cumulativeJenkinsArtifactPath,
            JenkinsValidationStatus cumulativeJenkinsStatus,
            RejectionStage rejectionStageIfRejected,
            String commitSha,
            List<String> conformanceViolations) {

        public ImplementationAttemptState {
            conformanceViolations = conformanceViolations == null ? List.of() : List.copyOf(conformanceViolations);
        }
    }

    public record GroupFinalOutcome(
            GroupFinalOutcomeKind kind,
            String commitSha,
            String humanReviewGroupKey,
            String summary) {
    }

    public record GroupPublicationOutcome(
            String mergeRequestUrl,
            String issueUrl,
            String status) {
    }
}
