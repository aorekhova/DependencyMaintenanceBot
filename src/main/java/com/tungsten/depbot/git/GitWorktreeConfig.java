package com.tungsten.depbot.git;

import com.tungsten.depbot.config.ConfigurationException;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Where the WebApplication repository lives, read from the process environment.
 *
 * <p>Not hardcoded: an absolute local path is machine-specific, and this application already has a
 * precedent (see {@code EnvConfig}) for keeping every environment-dependent value out of source
 * and behind an environment variable instead.
 */
public record GitWorktreeConfig(Path repoPath) {

    public static final String WEBAPP_REPO_PATH = "WEBAPP_REPO_PATH";

    /** Reads the repository path from the real process environment. */
    public static GitWorktreeConfig fromEnvironment() {
        return fromEnvironment(System.getenv());
    }

    /**
     * Reads the repository path from the supplied map.
     *
     * <p>Package-private so tests can inject values, for the same reason as {@code EnvConfig}:
     * {@code System.getenv()} cannot be mutated reliably from within a JVM.
     */
    static GitWorktreeConfig fromEnvironment(Map<String, String> environment) {
        String value = environment == null ? null : environment.get(WEBAPP_REPO_PATH);
        if (value == null || value.isBlank()) {
            throw new ConfigurationException("Missing required environment variable: " + WEBAPP_REPO_PATH);
        }

        Path path = Path.of(value.strip());
        if (!Files.isDirectory(path)) {
            throw new ConfigurationException(
                    WEBAPP_REPO_PATH + " does not point to an existing directory: " + path);
        }
        return new GitWorktreeConfig(path);
    }
}
