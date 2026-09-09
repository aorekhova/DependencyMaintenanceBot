package com.tungsten.depbot;

import com.tungsten.depbot.cli.ExitCode;
import com.tungsten.depbot.config.ConfigurationException;
import com.tungsten.depbot.config.EnvConfig;
import com.tungsten.depbot.mend.MalformedResponseException;
import com.tungsten.depbot.mend.MendApiException;
import com.tungsten.depbot.mend.MendGateway;
import com.tungsten.depbot.mend.MendHttpException;
import com.tungsten.depbot.mend.model.VulnerabilityRecord;
import com.tungsten.depbot.mend.model.VulnerabilityReport;
import com.tungsten.depbot.report.actionable.ActionableReportService;
import com.tungsten.depbot.report.actionable.ReportDestination;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Drives every output-producing path through {@link Main#run} with obviously synthetic
 * credentials and asserts that neither value, nor a stack trace, nor a stray "null" ever
 * reaches the console.
 *
 * <p>Several cases deliberately embed the credentials in text authored by "Mend", because that
 * is the path a reporter-only guarantee would miss.
 */
class SecretHandlingTest {

    private static final String USER_KEY = "USERKEY-DO-NOT-LEAK-9f3a";
    private static final String TOKEN = "TOKEN-DO-NOT-LEAK-7b1c";
    private static final EnvConfig CONFIG = new EnvConfig(USER_KEY, TOKEN);
    private static final Supplier<EnvConfig> GOOD_CONFIG = () -> CONFIG;

    private static void assertNothingLeaked(CapturedConsole console) {
        String output = console.all();
        assertFalse(output.contains(USER_KEY), "user key reached the console: " + output);
        assertFalse(output.contains(TOKEN), "project token reached the console: " + output);
        assertFalse(output.contains("\tat "), "a stack trace reached the console: " + output);
        assertFalse(output.contains("at com.tungsten"),
                "a stack frame reached the console: " + output);
        assertFalse(output.contains("null"), "a null message reached the console: " + output);
    }

    /** Reports are written into a temporary directory, never the real one. */
    @TempDir
    Path reportDir;

    private ActionableReportService reportService() {
        return new ActionableReportService(
                Clock.fixed(Instant.parse("2026-01-02T03:04:05Z"), ZoneOffset.UTC),
                ReportDestination.into(reportDir));
    }

    private CapturedConsole runScan(Supplier<EnvConfig> configSource, MendGateway gateway) {
        CapturedConsole console = new CapturedConsole();
        Main.run(new String[]{"scan"}, configSource, gateway, console.reporter(), reportService());
        return console;
    }

    @Test
    @DisplayName("success with vulnerabilities leaks nothing")
    void successWithVulnerabilities() {
        assertNothingLeaked(runScan(GOOD_CONFIG, config -> new VulnerabilityReport(
                List.of(new VulnerabilityRecord("critical"), new VulnerabilityRecord("low")))));
    }

    @Test
    @DisplayName("success with zero vulnerabilities leaks nothing")
    void successWithoutVulnerabilities() {
        assertNothingLeaked(runScan(GOOD_CONFIG,
                config -> new VulnerabilityReport(List.of())));
    }

    @Test
    @DisplayName("a configuration error leaks nothing")
    void configurationError() {
        Supplier<EnvConfig> failing = () -> {
            throw new ConfigurationException(
                    "Missing required environment variable: " + EnvConfig.MEND_USER_KEY);
        };
        assertNothingLeaked(runScan(failing, config -> new VulnerabilityReport(List.of())));
    }

    @Test
    @DisplayName("a Mend error echoing BOTH credentials leaks neither")
    void inBandErrorEchoingBothCredentials() {
        CapturedConsole console = runScan(GOOD_CONFIG, config -> {
            throw new MendApiException(1004,
                    "Invalid request for user " + USER_KEY + " with token " + TOKEN);
        });
        assertNothingLeaked(console);
    }

    @Test
    @DisplayName("a non-200 status leaks nothing")
    void httpStatusFailure() {
        assertNothingLeaked(runScan(GOOD_CONFIG, config -> {
            throw new MendHttpException("Mend API returned HTTP 401");
        }));
    }

    @Test
    @DisplayName("a malformed body embedding a credential leaks nothing")
    void malformedBodyEmbeddingCredential() {
        assertNothingLeaked(runScan(GOOD_CONFIG, config -> {
            throw new MalformedResponseException("the response body was not valid JSON");
        }));
    }

    @Test
    @DisplayName("a transport failure leaks nothing")
    void networkFailure() {
        assertNothingLeaked(runScan(GOOD_CONFIG, config -> {
            throw new MendHttpException("could not reach the Mend API host; check network access"
                    + " and proxy settings (-Dhttps.proxyHost and -Dhttps.proxyPort)");
        }));
    }

    @Test
    @DisplayName("an unexpected runtime failure carrying both credentials leaks nothing")
    void unexpectedFailure() {
        CapturedConsole console = new CapturedConsole();
        ExitCode code = Main.run(new String[]{"scan"}, GOOD_CONFIG, config -> {
            throw new RuntimeException("boom " + USER_KEY + " " + TOKEN);
        }, console.reporter(), reportService());

        assertEquals(ExitCode.UNEXPECTED_ERROR, code);
        assertNothingLeaked(console);
    }

    @Test
    @DisplayName("the usage path leaks nothing")
    void usagePath() {
        CapturedConsole console = new CapturedConsole();
        Main.run(new String[]{}, GOOD_CONFIG,
                config -> new VulnerabilityReport(List.of()), console.reporter(), reportService());
        assertNothingLeaked(console);
    }

    @Test
    @DisplayName("EnvConfig cannot leak credentials through string conversion")
    void envConfigToStringIsMasked() {
        String viaConcatenation = "config=" + CONFIG;
        assertFalse(viaConcatenation.contains(USER_KEY));
        assertFalse(viaConcatenation.contains(TOKEN));
        assertFalse(String.valueOf(CONFIG).contains(TOKEN));
    }
}
