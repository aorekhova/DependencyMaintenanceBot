package com.tungsten.depbot.jenkins;

/**
 * The exact, never-collapsed outcome of one Jenkins validation attempt.
 *
 * <p>{@code COULD_NOT_TRIGGER} means the build was never even queued -- a crumb request failed, the
 * connection was refused, Jenkins returned an unexpected status to the trigger call itself. {@code
 * TIMED_OUT} means a build was queued and/or ran, but no definitive result (`building:false`) arrived
 * within the configured budget -- whether because the build is genuinely slow or because Jenkins became
 * unreachable partway through polling; the two are not distinguished, since in both cases nothing
 * definitive was learned. {@code SUCCESS}/{@code FAILED}/{@code ABORTED}/{@code UNSTABLE} are Jenkins's
 * own, actually-observed result. An unrecognised result string is treated as {@code FAILED}, never as
 * {@code SUCCESS} -- fail closed.
 */
public enum JenkinsValidationStatus {
    SUCCESS,
    FAILED,
    ABORTED,
    UNSTABLE,
    TIMED_OUT,
    COULD_NOT_TRIGGER;

    public boolean succeeded() {
        return this == SUCCESS;
    }
}
