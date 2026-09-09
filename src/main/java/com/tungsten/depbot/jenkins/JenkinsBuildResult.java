package com.tungsten.depbot.jenkins;

import java.util.Objects;

/**
 * What {@link JenkinsClient#waitForCompletion} actually observed: either a definitive Jenkins result
 * (a resolved build number/URL and a status among {@code SUCCESS}/{@code FAILED}/{@code ABORTED}/
 * {@code UNSTABLE}), or {@code TIMED_OUT} when no definitive result arrived within the configured
 * budget. Never {@code COULD_NOT_TRIGGER} -- that status belongs exclusively to a failed
 * {@link JenkinsClient#triggerBuild}, never to this method.
 */
public record JenkinsBuildResult(
        JenkinsValidationStatus status, Integer buildNumber, String buildUrl, Long durationMillis,
        String resultSummary) {

    public JenkinsBuildResult {
        Objects.requireNonNull(status, "status");
        if (status == JenkinsValidationStatus.COULD_NOT_TRIGGER) {
            throw new IllegalArgumentException(
                    "COULD_NOT_TRIGGER is never a waitForCompletion result -- it belongs to a failed trigger");
        }
    }
}
