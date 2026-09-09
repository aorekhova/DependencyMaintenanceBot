package com.tungsten.depbot.report;

/**
 * The plain numbers {@link ConsoleReporter#printRemediationRunSummary} prints, computed by the caller
 * from {@code RemediationSummary} -- kept here, in {@code report}, rather than as a method on that
 * remediation-package record, so this package's console output never has to depend on the remediation
 * domain model to describe what it prints. Every field is a distinct question a reader might ask about a
 * run, never a duplicate of another field under a different name: a library, a Claude-defined
 * remediation group and a commit are three different things that a run's own numbers must never blur
 * together, even though this codebase's one-commit-per-group invariant makes {@code automaticGroups} and
 * {@code commits} numerically identical today.
 */
public record RemediationRunSummaryCounts(
        long librariesRemediated,
        long automaticGroups,
        long commits,
        long fullyValidated,
        long buildValidationFailed,
        long isolatedJenkinsValidatedGroups,
        long integrationJenkinsAttemptedCohorts,
        long integrationJenkinsSucceededCohorts,
        long readyToPublishGroups,
        long humanReviewGroups,
        long humanReviewLibraries,
        long humanReviewRequired,
        long nothingToDo,
        long needsAHuman,
        long failures,
        long automaticRejectedWithReport,
        long automaticRejectedNoReport,
        long analysisIncompleteBatches,
        long analysisIncompleteFindings) {
}
