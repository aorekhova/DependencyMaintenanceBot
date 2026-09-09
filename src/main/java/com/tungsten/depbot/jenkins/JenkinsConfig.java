package com.tungsten.depbot.jenkins;

import com.tungsten.depbot.config.ConfigurationException;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/**
 * How to reach the Jenkins installation that runs {@code WebApplicationDependencyValidation}, read from
 * the process environment -- the same pattern {@code GitLabConfig}/{@code ClaudeConfig} already use.
 *
 * <p>{@code apiToken} is never logged, printed or included in any exception message this class itself
 * raises -- {@link #toString()} is overridden for exactly that reason.
 *
 * <p>{@code buildTimeout}/{@code pollInterval} are placeholders, not calibrated production defaults --
 * the same caveat {@code ClaudeConfig} already carries for its own batch-analysis budget: they keep the
 * mechanism (and its tests) meaningful, and are expected to be revised once a real pilot against the
 * actual Jenkins installation shows what they should be.
 */
public record JenkinsConfig(
        String baseUrl, String jobName, String username, String apiToken,
        Duration buildTimeout, Duration pollInterval) {

    public static final String JENKINS_BASE_URL = "JENKINS_BASE_URL";
    public static final String JENKINS_JOB_NAME = "JENKINS_JOB_NAME";
    public static final String JENKINS_USERNAME = "JENKINS_USERNAME";
    public static final String JENKINS_API_TOKEN = "JENKINS_API_TOKEN";
    public static final String JENKINS_BUILD_TIMEOUT_SECONDS = "JENKINS_BUILD_TIMEOUT_SECONDS";
    public static final String JENKINS_POLL_INTERVAL_SECONDS = "JENKINS_POLL_INTERVAL_SECONDS";

    public static final String DEFAULT_JOB_NAME = "WebApplicationDependencyValidation";
    /** Forty-five minutes. Placeholder -- see the class javadoc. */
    public static final int DEFAULT_BUILD_TIMEOUT_SECONDS = 2700;
    /** Fifteen seconds. Placeholder -- see the class javadoc. */
    public static final int DEFAULT_POLL_INTERVAL_SECONDS = 15;

    public JenkinsConfig {
        Objects.requireNonNull(baseUrl, "baseUrl");
        Objects.requireNonNull(jobName, "jobName");
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(apiToken, "apiToken");
        Objects.requireNonNull(buildTimeout, "buildTimeout");
        Objects.requireNonNull(pollInterval, "pollInterval");
    }

    /**
     * @throws ConfigurationException if the base URL, username or token is missing -- there is no
     *                                sensible default for any of the three, unlike the rest
     */
    public static JenkinsConfig fromEnvironment(Map<String, String> environment) {
        return new JenkinsConfig(
                required(environment, JENKINS_BASE_URL),
                text(environment, JENKINS_JOB_NAME, DEFAULT_JOB_NAME),
                required(environment, JENKINS_USERNAME),
                required(environment, JENKINS_API_TOKEN),
                Duration.ofSeconds(positiveInt(environment, JENKINS_BUILD_TIMEOUT_SECONDS, DEFAULT_BUILD_TIMEOUT_SECONDS)),
                Duration.ofSeconds(positiveInt(environment, JENKINS_POLL_INTERVAL_SECONDS, DEFAULT_POLL_INTERVAL_SECONDS)));
    }

    private static String required(Map<String, String> environment, String name) {
        String value = environment == null ? null : environment.get(name);
        if (value == null || value.isBlank()) {
            throw new ConfigurationException(name + " must be set to run the Jenkins validation gate.");
        }
        return value.strip();
    }

    private static String text(Map<String, String> environment, String name, String fallback) {
        String value = environment == null ? null : environment.get(name);
        return (value == null || value.isBlank()) ? fallback : value.strip();
    }

    private static int positiveInt(Map<String, String> environment, String name, int fallback) {
        String value = environment == null ? null : environment.get(name);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        int parsed;
        try {
            parsed = Integer.parseInt(value.strip());
        } catch (NumberFormatException e) {
            throw new ConfigurationException(name + " must be a whole number, but was: " + value.strip());
        }
        if (parsed <= 0) {
            throw new ConfigurationException(name + " must be greater than zero, but was: " + parsed);
        }
        return parsed;
    }

    /** Never the token -- deliberately overridden so logging this object cannot leak it by accident. */
    @Override
    public String toString() {
        return "JenkinsConfig[baseUrl=" + baseUrl + ", jobName=" + jobName + ", username=" + username
                + ", apiToken=***, buildTimeout=" + buildTimeout + ", pollInterval=" + pollInterval + "]";
    }
}
