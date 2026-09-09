package com.tungsten.depbot.jenkins;

import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.git.GitTestRepos;
import com.tungsten.depbot.report.SecretRedactor;
import com.tungsten.depbot.run.RemediationRunService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fast regression tests for the Jenkins console-log gap-fill: {@link FakeJenkinsClient#fetchConsoleLog}
 * is only ever consulted on a non-{@code SUCCESS} outcome, and whatever it returns is redacted before
 * being written to disk or exposed on {@link JenkinsValidationOutcome}.
 */
class JenkinsConsoleLogFetchTest {

    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-08-20T10:00:00Z"), ZoneOffset.UTC);
    private static final String RUN_ID = "run1";
    private static final String UNIT_ID = "critical__org.example__lib";

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();
    private Path repo;
    private String baselineSha;
    private String candidateSha;
    private RemediationRunService runService;

    @BeforeEach
    void createRepository() throws IOException, InterruptedException {
        repo = GitTestRepos.createOriginAndClone(tempDir);
        baselineSha = GitTestRepos.shaOf(repo, "HEAD");
        Files.writeString(repo.resolve("file.txt"), "hello, changed\n", StandardCharsets.UTF_8);
        GitTestRepos.run(repo, "git", "commit", "-am", "candidate change");
        candidateSha = GitTestRepos.shaOf(repo, "HEAD");
        runService = new RemediationRunService(FIXED_CLOCK, tempDir.resolve("runs"));
    }

    private JenkinsConfig config() {
        return new JenkinsConfig("https://jenkins.example.invalid", "WebApplicationDependencyValidation",
                "bot", "TOKEN-DO-NOT-LEAK", Duration.ofSeconds(60), Duration.ofMillis(10));
    }

    private Path consoleLogPath() {
        return runService.unitDirectoryFor(RUN_ID, UNIT_ID)
                .resolve("jenkins-validation").resolve("attempt-1").resolve(JenkinsValidationService.CONSOLE_LOG_FILE);
    }

    @Test
    @DisplayName("a failed build fetches and persists a redacted console log")
    void failedBuildPersistsRedactedConsoleLog() {
        FakeJenkinsClient fake = new FakeJenkinsClient();
        fake.respondWith(new JenkinsBuildResult(
                JenkinsValidationStatus.FAILED, 7, "https://jenkins.example.invalid/job/x/7/", 10L,
                "Jenkins reported result FAILURE"));
        fake.respondToConsoleLogWith("build failed while using secret-token-abc123 to authenticate");

        JenkinsValidationService service = new JenkinsValidationService(
                fake, config(), git, runService, com.tungsten.depbot.progress.RemediationProgressListener.none(),
                SecretRedactor.of("secret-token-abc123"));

        JenkinsValidationOutcome outcome = service.validate(RUN_ID, UNIT_ID, repo, baselineSha, candidateSha);

        assertEquals(1, fake.fetchConsoleLogCount(), "the console log must be fetched exactly once");
        assertFalse(outcome.consoleLogExcerpt().contains("secret-token-abc123"), outcome.consoleLogExcerpt());
        assertTrue(outcome.consoleLogExcerpt().contains(SecretRedactor.MASK), outcome.consoleLogExcerpt());

        assertTrue(Files.exists(consoleLogPath()), "console-log.txt must be written to disk");
        String persisted = readString(consoleLogPath());
        assertFalse(persisted.contains("secret-token-abc123"), persisted);
        assertTrue(persisted.contains(SecretRedactor.MASK), persisted);
    }

    @Test
    @DisplayName("a successful build never fetches a console log")
    void successfulBuildNeverFetchesConsoleLog() {
        FakeJenkinsClient fake = new FakeJenkinsClient();
        fake.respondWith(new JenkinsBuildResult(
                JenkinsValidationStatus.SUCCESS, 7, "https://jenkins.example.invalid/job/x/7/", 10L,
                "Jenkins reported result SUCCESS"));

        JenkinsValidationService service = new JenkinsValidationService(fake, config(), git, runService);
        JenkinsValidationOutcome outcome = service.validate(RUN_ID, UNIT_ID, repo, baselineSha, candidateSha);

        assertEquals(0, fake.fetchConsoleLogCount());
        assertEquals(null, outcome.consoleLogExcerpt());
        assertFalse(Files.exists(consoleLogPath()));
    }

    private static String readString(Path path) {
        try {
            return Files.readString(path, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
