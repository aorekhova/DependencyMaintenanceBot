package com.tungsten.depbot.jenkins;

import java.time.Duration;

/**
 * The narrow slice of the Jenkins Remote API this application ever calls: trigger the
 * {@code WebApplicationDependencyValidation} job with its three parameters, then poll for its result.
 *
 * <p>A real implementation ({@code JenkinsApiClient}) talks to the actual Jenkins Remote API; tests use
 * an in-memory fake that never touches the network. Deliberately just these two methods -- all
 * queue-to-build resolution complexity lives inside the real client, not in this contract.
 */
public interface JenkinsClient {

    /**
     * Queues a new build. Throws {@link JenkinsValidationException} if the build could not even be
     * queued -- the only condition {@code JenkinsValidationService} maps to {@code COULD_NOT_TRIGGER}.
     */
    JenkinsBuildRef triggerBuild(JenkinsCandidate candidate);

    /**
     * Polls {@code ref} until Jenkins reports a definitive result or {@code timeout} elapses.
     *
     * <p>Never throws for an ordinary, transient per-poll network hiccup -- those are retried internally
     * until either a definitive result arrives or {@code timeout} is exhausted, at which point this
     * returns (never throws) a result with status {@code TIMED_OUT}. {@code heartbeat} is called between
     * poll attempts so a long wait is never silent.
     */
    JenkinsBuildResult waitForCompletion(
            JenkinsBuildRef ref, Duration timeout, Duration pollInterval, Runnable heartbeat);

    /**
     * The full console log text of a specific, already-numbered build -- called only when a validation
     * outcome did not succeed, so a repair cycle or a Human Review dossier has the same evidence a person
     * would look at first. Never throws for an ordinary network hiccup or a build whose log is not (yet)
     * available -- returns an empty string instead, exactly like a transient poll failure elsewhere in
     * this interface is never fatal.
     */
    String fetchConsoleLog(int buildNumber);
}
