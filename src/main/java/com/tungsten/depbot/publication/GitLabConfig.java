package com.tungsten.depbot.publication;

import com.tungsten.depbot.config.ConfigurationException;

import java.util.Map;
import java.util.Objects;

/**
 * How to reach the GitLab project this run's remediation branch belongs to, read from the process
 * environment -- the same pattern {@code ClaudeConfig}/{@code EnvConfig} already use.
 *
 * <p>{@code privateToken} is never logged, printed or included in any exception message this class
 * itself raises -- {@link #toString()} is overridden for exactly that reason; a record's generated
 * {@code toString()} would otherwise print every component, token included, the moment anything logs
 * this object.
 */
public record GitLabConfig(String baseUrl, String projectId, String privateToken, String remoteName) {

    public static final String GITLAB_BASE_URL = "GITLAB_BASE_URL";
    public static final String GITLAB_PROJECT_ID = "GITLAB_PROJECT_ID";
    public static final String GITLAB_PRIVATE_TOKEN = "GITLAB_PRIVATE_TOKEN";
    public static final String GITLAB_REMOTE_NAME = "GITLAB_REMOTE_NAME";

    public static final String DEFAULT_REMOTE_NAME = "origin";

    public GitLabConfig {
        Objects.requireNonNull(baseUrl, "baseUrl");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(privateToken, "privateToken");
        Objects.requireNonNull(remoteName, "remoteName");
    }

    /**
     * @throws ConfigurationException if the base URL, project id or token is missing -- there is no
     *                                sensible default for any of the three, unlike {@code remoteName}
     */
    public static GitLabConfig fromEnvironment(Map<String, String> environment) {
        return new GitLabConfig(
                required(environment, GITLAB_BASE_URL),
                required(environment, GITLAB_PROJECT_ID),
                required(environment, GITLAB_PRIVATE_TOKEN),
                text(environment, GITLAB_REMOTE_NAME, DEFAULT_REMOTE_NAME));
    }

    private static String required(Map<String, String> environment, String name) {
        String value = environment == null ? null : environment.get(name);
        if (value == null || value.isBlank()) {
            throw new ConfigurationException(name + " must be set to publish to GitLab.");
        }
        return value.strip();
    }

    private static String text(Map<String, String> environment, String name, String fallback) {
        String value = environment == null ? null : environment.get(name);
        return (value == null || value.isBlank()) ? fallback : value.strip();
    }

    /** Never the token -- deliberately overridden so logging this object cannot leak it by accident. */
    @Override
    public String toString() {
        return "GitLabConfig[baseUrl=" + baseUrl + ", projectId=" + projectId
                + ", privateToken=***, remoteName=" + remoteName + "]";
    }
}
