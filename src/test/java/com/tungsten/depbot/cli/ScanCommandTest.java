package com.tungsten.depbot.cli;

import com.tungsten.depbot.CapturedConsole;
import com.tungsten.depbot.config.ConfigurationException;
import com.tungsten.depbot.config.EnvConfig;
import com.tungsten.depbot.mend.MalformedResponseException;
import com.tungsten.depbot.mend.MendApiException;
import com.tungsten.depbot.mend.MendGateway;
import com.tungsten.depbot.mend.MendHttpException;
import com.tungsten.depbot.mend.model.VulnerabilityRecord;
import com.tungsten.depbot.mend.model.VulnerabilityReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers every outcome-to-exit-code mapping using a fake {@link MendGateway}.
 *
 * <p>No socket is opened and the HTTP client is never subclassed: that is exactly why the
 * gateway seam exists.
 */
class ScanCommandTest {

    private static final String USER_KEY = "USERKEY-DO-NOT-LEAK-9f3a";
    private static final String TOKEN = "TOKEN-DO-NOT-LEAK-7b1c";
    private static final EnvConfig CONFIG = new EnvConfig(USER_KEY, TOKEN);
    private static final Supplier<EnvConfig> GOOD_CONFIG = () -> CONFIG;

    private static ExitCode run(CapturedConsole console,
                                Supplier<EnvConfig> configSource,
                                MendGateway gateway) {
        return new ScanCommand(configSource, gateway, console.reporter()).run();
    }

    @Test
    @DisplayName("a report with vulnerabilities still exits SUCCESS")
    void successWithVulnerabilities() {
        CapturedConsole console = new CapturedConsole();
        MendGateway gateway = config -> new VulnerabilityReport(List.of(
                new VulnerabilityRecord("high"), new VulnerabilityRecord("low")));

        assertEquals(ExitCode.SUCCESS, run(console, GOOD_CONFIG, gateway));
        assertTrue(console.out().contains("Total vulnerabilities: 2"));
        assertTrue(console.out().contains("Security result: VULNERABILITIES FOUND"));
        assertTrue(console.out().contains("Process result: SUCCESS"));
    }

    @Test
    @DisplayName("a clean report exits SUCCESS and says NO VULNERABILITIES FOUND")
    void successWithoutVulnerabilities() {
        CapturedConsole console = new CapturedConsole();
        MendGateway gateway = config -> new VulnerabilityReport(List.of());

        assertEquals(ExitCode.SUCCESS, run(console, GOOD_CONFIG, gateway));
        assertTrue(console.out().contains("Security result: NO VULNERABILITIES FOUND"));
    }

    @Test
    @DisplayName("missing configuration exits CONFIG_ERROR")
    void configurationFailure() {
        CapturedConsole console = new CapturedConsole();
        Supplier<EnvConfig> failing = () -> {
            throw new ConfigurationException(
                    "Missing required environment variable: " + EnvConfig.MEND_USER_KEY);
        };

        assertEquals(ExitCode.CONFIG_ERROR,
                run(console, failing, config -> new VulnerabilityReport(List.of())));
        assertTrue(console.err().contains(EnvConfig.MEND_USER_KEY));
    }

    @Test
    @DisplayName("a Mend in-band error exits API_ERROR")
    void apiFailure() {
        CapturedConsole console = new CapturedConsole();
        MendGateway gateway = config -> {
            throw new MendApiException(1004, "Invalid project token");
        };

        assertEquals(ExitCode.API_ERROR, run(console, GOOD_CONFIG, gateway));
        assertTrue(console.err().contains("1004"));
    }

    @Test
    @DisplayName("a transport failure exits NETWORK_ERROR")
    void networkFailure() {
        CapturedConsole console = new CapturedConsole();
        MendGateway gateway = config -> {
            throw new MendHttpException("the request to the Mend API timed out");
        };

        assertEquals(ExitCode.NETWORK_ERROR, run(console, GOOD_CONFIG, gateway));
        assertTrue(console.err().contains("timed out"));
    }

    @Test
    @DisplayName("an unusable body exits MALFORMED_RESPONSE without echoing it")
    void malformedFailure() {
        CapturedConsole console = new CapturedConsole();
        MendGateway gateway = config -> {
            throw new MalformedResponseException("the vulnerabilities field was null");
        };

        assertEquals(ExitCode.MALFORMED_RESPONSE, run(console, GOOD_CONFIG, gateway));
        assertTrue(console.err().contains("could not be understood"));
    }

    @Test
    @DisplayName("an unexpected runtime failure exits UNEXPECTED_ERROR with no stack trace")
    void unexpectedFailure() {
        CapturedConsole console = new CapturedConsole();
        MendGateway gateway = config -> {
            throw new IllegalArgumentException("boom " + TOKEN);
        };

        assertEquals(ExitCode.UNEXPECTED_ERROR, run(console, GOOD_CONFIG, gateway));
        assertFalse(console.all().contains(TOKEN), "credential leaked on the unexpected path");
        assertFalse(console.all().contains("\tat "), "a stack trace reached the console");
        assertFalse(console.all().contains("boom"), "raw exception text reached the console");
    }

    @Test
    @DisplayName("an unexpected failure while loading configuration exits UNEXPECTED_ERROR")
    void unexpectedConfigurationFailure() {
        CapturedConsole console = new CapturedConsole();
        Supplier<EnvConfig> exploding = () -> {
            throw new IllegalStateException("some unrelated internal failure");
        };

        assertEquals(ExitCode.UNEXPECTED_ERROR,
                run(console, exploding, config -> new VulnerabilityReport(List.of())));
        assertFalse(console.all().contains("unrelated internal failure"));
    }

    @Test
    @DisplayName("the config-error path runs before any secret exists")
    void configErrorPathPrecedesSecrets() {
        CapturedConsole console = new CapturedConsole();
        Supplier<EnvConfig> failing = () -> {
            throw new ConfigurationException(
                    "Missing required environment variable: " + EnvConfig.MEND_PROJECT_TOKEN);
        };

        run(console, failing, config -> new VulnerabilityReport(List.of()));

        // Nothing to redact yet, and nothing secret should have been printed either.
        assertFalse(console.all().contains(USER_KEY));
        assertFalse(console.all().contains(TOKEN));
    }

    @Test
    @DisplayName("a Mend error message echoing a credential is redacted")
    void mendAuthoredMessageIsRedacted() {
        CapturedConsole console = new CapturedConsole();
        MendGateway gateway = config -> {
            // Mend authors this text, so it is untrusted: it could echo what we sent.
            throw new MendApiException(1004, "Invalid project token " + TOKEN);
        };

        assertEquals(ExitCode.API_ERROR, run(console, GOOD_CONFIG, gateway));
        assertFalse(console.all().contains(TOKEN),
                "withSecrets was not applied before printing Mend-authored text");
        assertTrue(console.err().contains("***"));
        assertTrue(console.err().contains("1004"));
    }

    @Test
    @DisplayName("a network message echoing the user key is redacted")
    void networkMessageIsRedacted() {
        CapturedConsole console = new CapturedConsole();
        MendGateway gateway = config -> {
            throw new MendHttpException("failed for user " + USER_KEY);
        };

        assertEquals(ExitCode.NETWORK_ERROR, run(console, GOOD_CONFIG, gateway));
        assertFalse(console.all().contains(USER_KEY));
    }

    @Test
    @DisplayName("a report with a null vulnerabilities list does not crash")
    void nullVulnerabilityListIsSafe() {
        CapturedConsole console = new CapturedConsole();
        MendGateway gateway = config -> new VulnerabilityReport(null);

        assertEquals(ExitCode.SUCCESS, run(console, GOOD_CONFIG, gateway));
        assertTrue(console.out().contains("Total vulnerabilities: 0"));
    }
}
