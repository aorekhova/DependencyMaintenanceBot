package com.tungsten.depbot.remediation;

import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;

import java.util.List;
import java.util.Objects;

/**
 * The bot-assembled, structured record of why a cohort's final-integration Jenkins gate failed, even
 * though every individual group in it was already accepted into the cumulative chain -- every field
 * programmatically filled, never Claude's unverified word for a structural fact, the same philosophy as
 * {@link RejectedGroupOutcome}.
 *
 * <p><strong>Never attributed to one specific group.</strong> A final-integration failure typically means
 * the *combination* of already-individually-valid groups does not build/pass together -- a fact about the
 * whole assembled set, not about any one member. {@code attributionNote} is always populated, and is never
 * a guess at which group is "really" to blame.
 *
 * <p>{@code verifiedSourceSha} is always {@code S0}, the cohort's one verified starting point --
 * {@code cumulativePatch}/{@code reproductionInstructions} are both anchored to it, never to any single
 * group's own {@code acceptedBaseSha}, since this failure is about the whole set.
 */
public record CohortIntegrationFailureOutcome(
        String schemaVersion,
        String branchName,
        String verifiedSourceRef,
        String verifiedSourceSha,
        List<String> acceptedGroupIds,
        List<CohortsIndex.Commit> acceptedCommits,
        String cumulativePatch,
        JenkinsValidationOutcome integrationJenkinsValidation,
        String jenkinsConsoleLogExcerpt,
        List<String> perGroupValidationSummaries,
        String failureReason,
        String attributionNote,
        String reproductionInstructions) {

    public static final String CURRENT_SCHEMA_VERSION = "1.0";

    public CohortIntegrationFailureOutcome {
        schemaVersion = (schemaVersion == null || schemaVersion.isBlank())
                ? CURRENT_SCHEMA_VERSION : schemaVersion.strip();
        Objects.requireNonNull(branchName, "branchName");
        Objects.requireNonNull(verifiedSourceRef, "verifiedSourceRef");
        Objects.requireNonNull(verifiedSourceSha, "verifiedSourceSha");
        Objects.requireNonNull(integrationJenkinsValidation, "integrationJenkinsValidation");
        Objects.requireNonNull(failureReason, "failureReason");
        Objects.requireNonNull(attributionNote, "attributionNote");
        acceptedGroupIds = acceptedGroupIds == null ? List.of() : List.copyOf(acceptedGroupIds);
        acceptedCommits = acceptedCommits == null ? List.of() : List.copyOf(acceptedCommits);
        perGroupValidationSummaries = perGroupValidationSummaries == null
                ? List.of() : List.copyOf(perGroupValidationSummaries);
    }
}
