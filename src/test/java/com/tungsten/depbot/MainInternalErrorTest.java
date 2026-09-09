package com.tungsten.depbot;

import com.tungsten.depbot.claude.ClaudeConfig;
import com.tungsten.depbot.cli.ExitCode;
import com.tungsten.depbot.config.ConfigurationException;
import com.tungsten.depbot.diagnostics.DiagnosticLog;
import com.tungsten.depbot.git.GitWorktreeConfig;
import com.tungsten.depbot.jenkins.JenkinsConfig;
import com.tungsten.depbot.mend.MendGateway;
import com.tungsten.depbot.publication.GitLabConfig;
import com.tungsten.depbot.mend.model.VulnerabilityReport;
import com.tungsten.depbot.report.SecretRedactor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression coverage for the failure the first jackson-databind pilot hit: {@code remediate} printed
 * "An unexpected internal error occurred", created no run, wrote no artifacts, and left no trace of what
 * had actually gone wrong.
 *
 * <p>The cause was structural, not anything to do with jackson. {@code remediate} reads
 * {@code WEBAPP_REPO_PATH} and the Claude settings while <em>wiring</em> its pipeline, because it needs
 * them to build it at all -- unlike {@code scan}, which is handed a {@code Supplier} and resolves its
 * configuration inside the command where a {@link ConfigurationException} is caught and reported. A
 * configuration problem in the remediate path therefore escaped every command's handling and landed in the
 * last-resort {@code Throwable} handler, which by design says nothing.
 */
class MainInternalErrorTest {

    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-08-11T04:30:00Z"), ZoneOffset.UTC);
    private static final MendGateway EMPTY_REPORT = config -> new VulnerabilityReport(List.of());
    private static final String[] JACKSON_PILOT =
            {"remediate", "--dependency", "com.fasterxml.jackson.core:jackson-databind"};

    /**
     * Never actually resolved in {@link #missingRepositoryPathIsAConfigurationError}/
     * {@link #unusableClaudeSettingIsAConfigurationError}: {@code Main.remediateCommand} reads this
     * supplier strictly last, after both of the earlier ones, which throw first in both of those tests.
     */
    private static final java.util.function.Supplier<JenkinsConfig> UNUSED_JENKINS_CONFIG =
            () -> new JenkinsConfig("http://unused.invalid", "job", "user", "token",
                    java.time.Duration.ofSeconds(60), java.time.Duration.ofSeconds(1));

    /**
     * Never actually resolved in any of the three "an earlier supplier throws first" tests below:
     * {@code Main.remediateCommand} reads this supplier strictly last, after Jenkins.
     */
    private static final java.util.function.Supplier<GitLabConfig> UNUSED_GITLAB_CONFIG =
            () -> new GitLabConfig("https://unused.invalid", "0", "unused-token", "origin");

    @TempDir
    Path tempDir;

    private DiagnosticLog diagnostics() {
        return diagnostics(SecretRedactor.none());
    }

    private DiagnosticLog diagnostics(SecretRedactor redactor) {
        return new DiagnosticLog(tempDir.resolve("diagnostics"), FIXED_CLOCK, redactor);
    }

    private List<Path> recordedLogs() throws IOException {
        Path directory = tempDir.resolve("diagnostics");
        if (!Files.exists(directory)) {
            return List.of();
        }
        try (Stream<Path> entries = Files.list(directory)) {
            return entries.toList();
        }
    }

    private String onlyRecordedLog() throws IOException {
        List<Path> logs = recordedLogs();
        assertEquals(1, logs.size(), "expected exactly one diagnostic file, got " + logs);
        return Files.readString(logs.get(0), StandardCharsets.UTF_8);
    }

    // ---- the regression itself -------------------------------------------------------------------

    @Test
    @DisplayName("a missing WEBAPP_REPO_PATH is a configuration error, not an internal one")
    void missingRepositoryPathIsAConfigurationError() {
        CapturedConsole console = new CapturedConsole();

        ExitCode code = Main.guarded(
                () -> Main.runRemediate(JACKSON_PILOT, console.reporter(), Main.remediateCommand(
                        EMPTY_REPORT, console.reporter(),
                        // Exactly what GitWorktreeConfig throws when the variable is absent; that it
                        // throws it is GitWorktreeConfigTest's subject, not this one's.
                        () -> {
                            throw new ConfigurationException(
                                    "Missing required environment variable: WEBAPP_REPO_PATH");
                        },
                        () -> ClaudeConfig.fromEnvironment(Map.of()), UNUSED_JENKINS_CONFIG, UNUSED_GITLAB_CONFIG)),
                console.reporter(), diagnostics(), Main.describe(JACKSON_PILOT));

        assertEquals(ExitCode.CONFIG_ERROR, code,
                "the operator can fix this in one command; telling them it was internal cannot be acted on");
        assertTrue(console.err().contains("WEBAPP_REPO_PATH"), console.err());
        assertFalse(console.err().contains("unexpected internal error"), console.err());
    }

    @Test
    @DisplayName("an unusable Claude setting is a configuration error too, wherever it is read")
    void unusableClaudeSettingIsAConfigurationError() {
        CapturedConsole console = new CapturedConsole();

        ExitCode code = Main.guarded(
                () -> Main.runRemediate(JACKSON_PILOT, console.reporter(), Main.remediateCommand(
                        EMPTY_REPORT, console.reporter(),
                        () -> new GitWorktreeConfig(tempDir),
                        () -> ClaudeConfig.fromEnvironment(
                                Map.of(ClaudeConfig.CLAUDE_MAX_TURNS, "not-a-number")), UNUSED_JENKINS_CONFIG,
                        UNUSED_GITLAB_CONFIG)),
                console.reporter(), diagnostics(), Main.describe(JACKSON_PILOT));

        assertEquals(ExitCode.CONFIG_ERROR, code);
        assertTrue(console.err().contains(ClaudeConfig.CLAUDE_MAX_TURNS), console.err());
    }

    @Test
    @DisplayName("a missing Jenkins setting is a configuration error too, wherever it is read")
    void missingJenkinsSettingIsAConfigurationError() {
        CapturedConsole console = new CapturedConsole();

        ExitCode code = Main.guarded(
                () -> Main.runRemediate(JACKSON_PILOT, console.reporter(), Main.remediateCommand(
                        EMPTY_REPORT, console.reporter(),
                        () -> new GitWorktreeConfig(tempDir),
                        () -> ClaudeConfig.fromEnvironment(Map.of()),
                        () -> JenkinsConfig.fromEnvironment(Map.of()), UNUSED_GITLAB_CONFIG)),
                console.reporter(), diagnostics(), Main.describe(JACKSON_PILOT));

        assertEquals(ExitCode.CONFIG_ERROR, code);
        assertTrue(console.err().contains(JenkinsConfig.JENKINS_BASE_URL), console.err());
    }

    @Test
    @DisplayName("a missing GitLab setting is a configuration error too, read strictly last")
    void missingGitLabSettingIsAConfigurationError() {
        CapturedConsole console = new CapturedConsole();

        ExitCode code = Main.guarded(
                () -> Main.runRemediate(JACKSON_PILOT, console.reporter(), Main.remediateCommand(
                        EMPTY_REPORT, console.reporter(),
                        () -> new GitWorktreeConfig(tempDir),
                        () -> ClaudeConfig.fromEnvironment(Map.of()),
                        UNUSED_JENKINS_CONFIG,
                        () -> GitLabConfig.fromEnvironment(Map.of()))),
                console.reporter(), diagnostics(), Main.describe(JACKSON_PILOT));

        assertEquals(ExitCode.CONFIG_ERROR, code);
        assertTrue(console.err().contains(GitLabConfig.GITLAB_BASE_URL), console.err());
    }

    @Test
    @DisplayName("a configuration error records no diagnostic file, because nothing is unexplained")
    void aConfigurationErrorNeedsNoDiagnosticFile() throws Exception {
        CapturedConsole console = new CapturedConsole();

        Main.guarded(() -> {
            throw new ConfigurationException("Missing required environment variable: WEBAPP_REPO_PATH");
        }, console.reporter(), diagnostics(), Main.describe(JACKSON_PILOT));

        assertEquals(List.of(), recordedLogs());
    }

    // ---- what a genuinely unexpected failure now leaves behind ------------------------------------

    @Test
    @DisplayName("an unexpected failure still says nothing on the console, but is recorded")
    void unexpectedFailureIsRecordedRatherThanLost() throws Exception {
        CapturedConsole console = new CapturedConsole();

        ExitCode code = Main.guarded(() -> {
            throw new IllegalStateException("something deep in the pipeline gave up");
        }, console.reporter(), diagnostics(), Main.describe(JACKSON_PILOT));

        assertEquals(ExitCode.UNEXPECTED_ERROR, code);
        assertTrue(console.err().contains("unexpected internal error"), console.err());
        assertFalse(console.err().contains("something deep in the pipeline gave up"),
                "the console must still refuse to show details: " + console.err());
        assertTrue(console.err().contains("Diagnostic details"), console.err());

        String log = onlyRecordedLog();
        assertTrue(log.contains("java.lang.IllegalStateException"), log);
        assertTrue(log.contains("something deep in the pipeline gave up"), log);
        assertTrue(log.contains("MainInternalErrorTest"), "the stack trace must be there: " + log);
        assertTrue(log.contains("remediate --dependency com.fasterxml.jackson.core:jackson-databind"), log);
    }

    @Test
    @DisplayName("the cause chain is recorded, since the top exception is rarely the interesting one")
    void causeChainIsRecorded() throws Exception {
        CapturedConsole console = new CapturedConsole();

        Main.guarded(() -> {
            throw new IllegalStateException("wrapper", new IllegalArgumentException("the real problem"));
        }, console.reporter(), diagnostics(), "remediate");

        String log = onlyRecordedLog();
        assertTrue(log.contains("Caused by"), log);
        assertTrue(log.contains("the real problem"), log);
    }

    @Test
    @DisplayName("credentials are masked out of the diagnostic file, message and stack trace alike")
    void credentialsAreMaskedOutOfTheDiagnosticFile() throws Exception {
        CapturedConsole console = new CapturedConsole();
        String userKey = "USERKEY-DO-NOT-LEAK-9f3a";
        String projectToken = "TOKEN-DO-NOT-LEAK-7b1c";

        Main.guarded(() -> {
            throw new IllegalStateException("Mend said: " + userKey + " rejected, token " + projectToken);
        }, console.reporter(), diagnostics(SecretRedactor.of(userKey, projectToken)), "remediate");

        String log = onlyRecordedLog();
        assertFalse(log.contains(userKey), "a credential reached the diagnostic file");
        assertFalse(log.contains(projectToken), "a credential reached the diagnostic file");
        assertTrue(log.contains(SecretRedactor.MASK), log);
    }

    @Test
    @DisplayName("the diagnostic file states that no environment values are in it")
    void diagnosticFileStatesWhatItDoesNotContain() throws Exception {
        CapturedConsole console = new CapturedConsole();

        Main.guarded(() -> {
            throw new IllegalStateException("boom");
        }, console.reporter(), diagnostics(), "remediate");

        assertTrue(onlyRecordedLog().contains("No environment variable values"), onlyRecordedLog());
    }

    @Test
    @DisplayName("a diagnostic log that cannot be written does not replace the original failure")
    void anUnwritableDiagnosticLogDoesNotBecomeTheFailure() throws Exception {
        CapturedConsole console = new CapturedConsole();
        // A file where the directory has to go: creating the directory cannot succeed.
        Path blocked = tempDir.resolve("blocked");
        Files.writeString(blocked, "not a directory", StandardCharsets.UTF_8);
        DiagnosticLog unwritable = new DiagnosticLog(blocked, FIXED_CLOCK, SecretRedactor.none());

        ExitCode code = Main.guarded(() -> {
            throw new IllegalStateException("the original failure");
        }, console.reporter(), unwritable, "remediate");

        assertEquals(ExitCode.UNEXPECTED_ERROR, code, "the original failure still decides the exit code");
        assertTrue(console.err().contains("unexpected internal error"), console.err());
        assertTrue(console.err().contains("could not be written"), console.err());
    }

    @Test
    @DisplayName("a successful command records nothing and returns its own exit code")
    void aSuccessfulCommandRecordsNothing() throws Exception {
        CapturedConsole console = new CapturedConsole();

        ExitCode code = Main.guarded(
                () -> ExitCode.SUCCESS, console.reporter(), diagnostics(), "scan");

        assertEquals(ExitCode.SUCCESS, code);
        assertEquals(List.of(), recordedLogs());
        assertEquals("", console.err());
    }

    @Test
    @DisplayName("an error escaping any command, not just remediate, is recorded the same way")
    void theGuardCoversEveryCommand() throws Exception {
        CapturedConsole console = new CapturedConsole();

        Main.guarded(() -> {
            throw new OutOfMemoryError("simulated");
        }, console.reporter(), diagnostics(), Main.describe(new String[] {"scan"}));

        String log = onlyRecordedLog();
        assertTrue(log.contains("OutOfMemoryError"), log);
        assertTrue(log.contains("Context: scan"), log);
    }

    @Test
    @DisplayName("the recorded context is the command line, never anything read from the environment")
    void recordedContextIsOnlyTheCommandLine() {
        assertEquals("remediate --dependency com.fasterxml.jackson.core:jackson-databind",
                Main.describe(JACKSON_PILOT));
        assertEquals("no command", Main.describe(new String[0]));
        assertEquals("no command", Main.describe(null));
    }

    @Test
    @DisplayName("each internal error gets its own file, so one does not overwrite another")
    void eachFailureGetsItsOwnFile() throws Exception {
        CapturedConsole console = new CapturedConsole();
        DiagnosticLog diagnostics = diagnostics();

        for (int attempt = 0; attempt < 5; attempt++) {
            Path recorded = diagnostics.record("remediate", new IllegalStateException("failure"));
            assertNotNull(recorded);
        }

        assertEquals(5, recordedLogs().size());
        assertEquals("", console.out());
    }
}
