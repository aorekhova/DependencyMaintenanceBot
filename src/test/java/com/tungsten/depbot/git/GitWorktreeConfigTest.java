package com.tungsten.depbot.git;

import com.tungsten.depbot.config.ConfigurationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class GitWorktreeConfigTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("a valid directory is accepted as the repository path")
    void validDirectoryIsAccepted() {
        GitWorktreeConfig config =
                GitWorktreeConfig.fromEnvironment(Map.of(GitWorktreeConfig.WEBAPP_REPO_PATH, tempDir.toString()));
        assertEquals(tempDir.toString(), config.repoPath().toString());
    }

    @Test
    @DisplayName("a missing environment variable throws ConfigurationException")
    void missingVariableThrows() {
        assertThrows(ConfigurationException.class, () -> GitWorktreeConfig.fromEnvironment(Map.of()));
    }

    @Test
    @DisplayName("a blank environment variable throws ConfigurationException")
    void blankVariableThrows() {
        assertThrows(ConfigurationException.class,
                () -> GitWorktreeConfig.fromEnvironment(Map.of(GitWorktreeConfig.WEBAPP_REPO_PATH, "   ")));
    }

    @Test
    @DisplayName("a path that does not exist throws ConfigurationException")
    void nonExistentPathThrows() {
        Path missing = tempDir.resolve("does-not-exist");
        assertThrows(ConfigurationException.class,
                () -> GitWorktreeConfig.fromEnvironment(Map.of(GitWorktreeConfig.WEBAPP_REPO_PATH, missing.toString())));
    }

    @Test
    @DisplayName("a path that is a file, not a directory, throws ConfigurationException")
    void filePathThrows() throws Exception {
        Path file = tempDir.resolve("not-a-directory.txt");
        Files.writeString(file, "x", StandardCharsets.UTF_8);

        assertThrows(ConfigurationException.class,
                () -> GitWorktreeConfig.fromEnvironment(Map.of(GitWorktreeConfig.WEBAPP_REPO_PATH, file.toString())));
    }

    @Test
    @DisplayName("null environment throws ConfigurationException, not NullPointerException")
    void nullEnvironmentThrows() {
        assertThrows(ConfigurationException.class, () -> GitWorktreeConfig.fromEnvironment(null));
    }
}
