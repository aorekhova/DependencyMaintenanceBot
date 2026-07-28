package com.tungsten.depbot.report;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConsoleReporterTest {

    private static final String USER_KEY = "USERKEY-DO-NOT-LEAK-9f3a";
    private static final String TOKEN = "TOKEN-DO-NOT-LEAK-7b1c";

    private ByteArrayOutputStream outBuffer;
    private ByteArrayOutputStream errBuffer;
    private ConsoleReporter reporter;

    @BeforeEach
    void setUp() {
        outBuffer = new ByteArrayOutputStream();
        errBuffer = new ByteArrayOutputStream();
        reporter = new ConsoleReporter(
                new PrintStream(outBuffer, true, StandardCharsets.UTF_8),
                new PrintStream(errBuffer, true, StandardCharsets.UTF_8));
    }

    private String out() {
        return outBuffer.toString(StandardCharsets.UTF_8);
    }

    private String err() {
        return errBuffer.toString(StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("usage text is exact and goes to stderr")
    void usageGoesToStderr() {
        reporter.printUsage();
        assertEquals("Usage: java -jar dependency-maintenance-bot.jar scan",
                err().strip());
        assertEquals("", out());
    }

    @Test
    @DisplayName("report with vulnerabilities goes to stdout and says VULNERABILITIES FOUND")
    void reportWithVulnerabilities() {
        reporter.printReport(new SeverityCounts(7, 0, 4, 3, 0, 0));

        String text = out();
        assertTrue(text.contains("Mend vulnerability check completed"));
        assertTrue(text.contains("Total vulnerabilities: 7"));
        assertTrue(text.contains("Critical: 0"));
        assertTrue(text.contains("High: 4"));
        assertTrue(text.contains("Medium: 3"));
        assertTrue(text.contains("Low: 0"));
        assertTrue(text.contains("Other: 0"));
        assertTrue(text.contains("Process result: SUCCESS"));
        assertTrue(text.contains("Security result: VULNERABILITIES FOUND"));
        assertEquals("", err());
    }

    @Test
    @DisplayName("zero-vulnerability report says NO VULNERABILITIES FOUND")
    void reportWithoutVulnerabilities() {
        reporter.printReport(new SeverityCounts(0, 0, 0, 0, 0, 0));

        String text = out();
        assertTrue(text.contains("Total vulnerabilities: 0"));
        assertTrue(text.contains("Security result: NO VULNERABILITIES FOUND"));
        assertFalse(text.contains("Security result: VULNERABILITIES FOUND"));
    }

    @Test
    @DisplayName("process result and security result are separate lines")
    void processAndSecurityResultsAreDistinct() {
        reporter.printReport(new SeverityCounts(1, 1, 0, 0, 0, 0));
        assertTrue(out().lines().anyMatch(line -> line.equals("Process result: SUCCESS")));
        assertTrue(out().lines().anyMatch(line -> line.equals("Security result: VULNERABILITIES FOUND")));
    }

    @Test
    @DisplayName("all error output goes to stderr")
    void errorsGoToStderr() {
        reporter.printConfigError("Missing required environment variable: MEND_USER_KEY");
        reporter.printApiError(1004, "Invalid project token");
        reporter.printNetworkError("request timed out");
        reporter.printMalformedResponseError();
        reporter.printUnexpectedError();

        assertEquals("", out());
        assertTrue(err().contains("MEND_USER_KEY"));
        assertTrue(err().contains("1004"));
        assertTrue(err().contains("request timed out"));
    }

    @Test
    @DisplayName("withSecrets returns a new reporter and leaves the original un-seeded")
    void withSecretsIsImmutable() {
        ConsoleReporter secure = reporter.withSecrets(USER_KEY, TOKEN);
        assertNotSame(reporter, secure);

        // The original still has no secrets, so it does not redact.
        reporter.printApiError(1004, "token " + USER_KEY);
        assertTrue(err().contains(USER_KEY),
                "original reporter must not have been mutated by withSecrets");
    }

    @Test
    @DisplayName("an API error embedding the user key is redacted")
    void apiErrorRedactsUserKey() {
        reporter.withSecrets(USER_KEY, TOKEN)
                .printApiError(1004, "Invalid credentials for user " + USER_KEY);

        assertFalse(err().contains(USER_KEY));
        assertTrue(err().contains(SecretRedactor.MASK));
    }

    @Test
    @DisplayName("an API error embedding the project token is redacted")
    void apiErrorRedactsProjectToken() {
        reporter.withSecrets(USER_KEY, TOKEN)
                .printApiError(1004, "Invalid project token " + TOKEN);

        assertFalse(err().contains(TOKEN));
        assertTrue(err().contains(SecretRedactor.MASK));
    }

    @Test
    @DisplayName("all output is plain ASCII so a Cp1252 console cannot mangle it")
    void allOutputIsAscii() {
        reporter.printUsage();
        reporter.printReport(new SeverityCounts(3, 1, 1, 1, 0, 0));
        reporter.printConfigError("Missing required environment variable: MEND_USER_KEY");
        reporter.printApiError(1004, "Invalid project token");
        reporter.printNetworkError("connection timed out");
        reporter.printMalformedResponseError();
        reporter.printUnexpectedError();

        assertTrue((out() + err()).chars().allMatch(c -> c < 128),
                "reporter emitted a non-ASCII character");
    }
}
