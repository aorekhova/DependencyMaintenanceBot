package com.tungsten.depbot.jenkins;

import java.util.Objects;

/**
 * The bot-owned, structured record of one Jenkins validation attempt -- never a Claude paraphrase.
 * Used verbatim in three places: a {@code RemediationReport}'s own isolated/final-integration sections,
 * a {@code HumanReviewContext}/{@code HumanReviewReport}'s own Jenkins section, and this application's
 * internal {@code jenkins-result.json} artifact. Every field here is a fact this application itself
 * established (or a fact Jenkins itself reported), never something summarised or inferred by Claude.
 */
public record JenkinsValidationOutcome(
        JenkinsValidationStatus status,
        String jobName,
        Integer buildNumber,
        String buildUrl,
        String baselineSha,
        String candidateSha,
        String expectedTreeSha,
        Long durationSeconds,
        String resultSummary,
        String consoleLogExcerpt) {

    public JenkinsValidationOutcome {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(jobName, "jobName");
        Objects.requireNonNull(baselineSha, "baselineSha");
        Objects.requireNonNull(candidateSha, "candidateSha");
        Objects.requireNonNull(expectedTreeSha, "expectedTreeSha");
        Objects.requireNonNull(resultSummary, "resultSummary");
    }

    /** As the canonical constructor, with no console log excerpt -- every pre-existing call site. */
    public JenkinsValidationOutcome(
            JenkinsValidationStatus status, String jobName, Integer buildNumber, String buildUrl,
            String baselineSha, String candidateSha, String expectedTreeSha, Long durationSeconds,
            String resultSummary) {
        this(status, jobName, buildNumber, buildUrl, baselineSha, candidateSha, expectedTreeSha,
                durationSeconds, resultSummary, null);
    }

    public boolean succeeded() {
        return status.succeeded();
    }
}
