package com.tungsten.depbot;

import com.tungsten.depbot.cli.ExitCode;
import com.tungsten.depbot.config.ConfigurationException;
import com.tungsten.depbot.config.EnvConfig;
import com.tungsten.depbot.mend.MalformedResponseException;
import com.tungsten.depbot.mend.MendGateway;
import com.tungsten.depbot.mend.MendHttpException;
import com.tungsten.depbot.mend.model.VulnerabilityRecord;
import com.tungsten.depbot.mend.model.VulnerabilityReport;
import com.tungsten.depbot.report.actionable.ActionableReportService;
import com.tungsten.depbot.report.actionable.ReportDestination;
import com.tungsten.depbot.report.actionable.ReportWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Covers the stale-report contract at scan level.
 *
 * <p>Because the report filenames are fixed, a consumer reading them cannot tell a fresh report from
 * last week's. These tests pin the rule that makes absence meaningful: every scan removes the
 * previous pair first, so if the files are missing the last scan did not succeed.
 */
class StaleReportLifecycleTest {

    private static final String SENTINEL_JSON = "{\"generatedAt\":\"1999-01-01T00:00:00Z\"}";
    private static final String SENTINEL_MARKDOWN = "# Previous run from 1999";

    private static final EnvConfig CONFIG =
            new EnvConfig("USERKEY-DO-NOT-LEAK-9f3a", "TOKEN-DO-NOT-LEAK-7b1c");
    private static final Supplier<EnvConfig> GOOD_CONFIG = () -> CONFIG;
    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-01-02T03:04:05Z"), ZoneOffset.UTC);

    @TempDir
    Path reportDir;

    private ReportDestination destination;

    @BeforeEach
    void setUp() {
        destination = ReportDestination.into(reportDir);
    }

    private ActionableReportService service() {
        return new ActionableReportService(FIXED_CLOCK, destination);
    }

    private ActionableReportService service(ReportWriter writer) {
        return new ActionableReportService(FIXED_CLOCK, destination, writer);
    }

    /** Seeds a previous report pair that must not survive a failed scan. */
    private void seedPreviousReports() throws IOException {
        Files.writeString(destination.jsonPath(), SENTINEL_JSON, StandardCharsets.UTF_8);
        Files.writeString(destination.markdownPath(), SENTINEL_MARKDOWN, StandardCharsets.UTF_8);
    }

    private void assertBothReportsAbsent() {
        assertFalse(Files.exists(destination.jsonPath()),
                "a non-successful scan must not leave a JSON report looking current");
        assertFalse(Files.exists(destination.markdownPath()),
                "a non-successful scan must not leave a Markdown report looking current");
    }

    private ExitCode scan(CapturedConsole console, MendGateway gateway,
                          ActionableReportService reportService) {
        return Main.run(new String[]{"scan"}, GOOD_CONFIG, gateway, console.reporter(),
                reportService);
    }

    /** A directory containing a file cannot be deleted, so it blocks removal deterministically. */
    private static void obstruct(Path path) throws IOException {
        Files.createDirectories(path);
        Files.writeString(path.resolve("occupant.txt"), "not ours", StandardCharsets.UTF_8);
    }

    // ---------- the four required scenarios ----------

    @Test
    @DisplayName("previous files exist and the Mend API fails, so both are absent")
    void mendApiFailureLeavesNoReports() throws IOException {
        seedPreviousReports();
        CapturedConsole console = new CapturedConsole();

        ExitCode code = scan(console, config -> {
            throw new MendHttpException("Mend API returned HTTP 401");
        }, service());

        assertEquals(ExitCode.NETWORK_ERROR, code);
        assertBothReportsAbsent();
    }

    @Test
    @DisplayName("previous files exist and parsing fails, so both are absent")
    void parsingFailureLeavesNoReports() throws IOException {
        seedPreviousReports();
        CapturedConsole console = new CapturedConsole();

        ExitCode code = scan(console, config -> {
            throw new MalformedResponseException("the response body was not valid JSON");
        }, service());

        assertEquals(ExitCode.MALFORMED_RESPONSE, code);
        assertBothReportsAbsent();
    }

    @Test
    @DisplayName("previous files exist and a new scan succeeds, so both are replaced")
    void successfulScanReplacesBothReports() throws IOException {
        seedPreviousReports();
        CapturedConsole console = new CapturedConsole();

        ExitCode code = scan(console,
                config -> new VulnerabilityReport(List.of(new VulnerabilityRecord("high"))),
                service());

        assertEquals(ExitCode.SUCCESS, code);

        String json = Files.readString(destination.jsonPath(), StandardCharsets.UTF_8);
        String markdown = Files.readString(destination.markdownPath(), StandardCharsets.UTF_8);

        assertTrue(json.contains("2026-01-02T03:04:05Z"), "the new generation stamp is missing");
        assertFalse(json.contains("1999"), "content from the previous run survived");
        assertFalse(markdown.contains("1999"), "content from the previous run survived");
    }

    @Test
    @DisplayName("a failure to invalidate exits 6 and never contacts Mend")
    void invalidationFailureStopsBeforeMend() throws IOException {
        obstruct(destination.jsonPath());

        AtomicInteger mendCalls = new AtomicInteger();
        MendGateway shouldNotBeCalled = config -> {
            mendCalls.incrementAndGet();
            return fail("Mend must not be contacted when the report state cannot be guaranteed");
        };

        CapturedConsole console = new CapturedConsole();
        ExitCode code = scan(console, shouldNotBeCalled, service());

        assertEquals(ExitCode.REPORT_WRITE_ERROR, code);
        assertEquals(0, mendCalls.get(), "the scan must stop before any network call");
        assertTrue(console.err().contains("could not be guaranteed"),
                "the operator should be told the state is uncertain: " + console.err());
    }

    // ---------- other failure modes ----------

    @Test
    @DisplayName("a missing environment variable also leaves no report behind")
    void configurationFailureLeavesNoReports() throws IOException {
        seedPreviousReports();
        Supplier<EnvConfig> missing = () -> {
            throw new ConfigurationException(
                    "Missing required environment variable: " + EnvConfig.MEND_USER_KEY);
        };

        CapturedConsole console = new CapturedConsole();
        ExitCode code = Main.run(new String[]{"scan"}, missing,
                config -> new VulnerabilityReport(List.of()), console.reporter(), service());

        assertEquals(ExitCode.CONFIG_ERROR, code);
        // Invalidation runs before configuration precisely so this case is covered too.
        assertBothReportsAbsent();
    }

    @Test
    @DisplayName("an unexpected failure also leaves no report behind")
    void unexpectedFailureLeavesNoReports() throws IOException {
        seedPreviousReports();
        CapturedConsole console = new CapturedConsole();

        ExitCode code = scan(console, config -> {
            throw new IllegalStateException("something unexpected");
        }, service());

        assertEquals(ExitCode.UNEXPECTED_ERROR, code);
        assertBothReportsAbsent();
    }

    @Test
    @DisplayName("a usage error never touches the report directory")
    void usageErrorLeavesPreviousReportsAlone() throws IOException {
        seedPreviousReports();
        CapturedConsole console = new CapturedConsole();

        ExitCode code = Main.run(new String[]{"bogus"}, GOOD_CONFIG,
                config -> new VulnerabilityReport(List.of()), console.reporter(), service());

        assertEquals(ExitCode.USAGE_ERROR, code);
        // The user did not ask for a scan, so nothing about the report state should change.
        assertEquals(SENTINEL_JSON,
                Files.readString(destination.jsonPath(), StandardCharsets.UTF_8));
        assertEquals(SENTINEL_MARKDOWN,
                Files.readString(destination.markdownPath(), StandardCharsets.UTF_8));
    }

    // ---------- publication failure ----------

    @Test
    @DisplayName("a publication failure exits 6 after the summary was already printed")
    void publicationFailureAfterSummary() {
        CapturedConsole console = new CapturedConsole();
        ReportWriter failingWriter = new ReportWriter(failOnMove(2));

        ExitCode code = scan(console,
                config -> new VulnerabilityReport(List.of(new VulnerabilityRecord("critical"))),
                service(failingWriter));

        assertEquals(ExitCode.REPORT_WRITE_ERROR, code);
        assertTrue(console.out().contains("Mend vulnerability check completed"),
                "the operator should keep the scan's primary value even when the write fails");
        assertTrue(console.err().contains("Report write error"));
        assertBothReportsAbsent();
    }

    @Test
    @DisplayName("a publication failure with successful cleanup does not claim uncertainty")
    void publicationFailureWithCleanCleanup() {
        CapturedConsole console = new CapturedConsole();

        scan(console, config -> new VulnerabilityReport(List.of(new VulnerabilityRecord("high"))),
                service(new ReportWriter(failOnMove(2))));

        assertFalse(console.err().contains("could not be guaranteed"),
                "cleanup succeeded, so the operator should not be sent to inspect anything");
    }

    @Test
    @DisplayName("a publication failure with blocked cleanup reports the state as unknown")
    void publicationFailureWithBlockedCleanup() throws IOException {
        // The Markdown target is occupied by something that is not ours, so cleanup cannot
        // reconcile it. This is the honest limit of two-file publication.
        obstruct(destination.markdownPath());
        Path preserved = destination.markdownPath().resolve("occupant.txt");

        CapturedConsole console = new CapturedConsole();
        ExitCode code = Main.run(new String[]{"scan"}, GOOD_CONFIG,
                config -> new VulnerabilityReport(List.of(new VulnerabilityRecord("critical"))),
                console.reporter(),
                // A writer that cannot invalidate would stop earlier, so invalidation is skipped
                // here by giving the service a writer whose move fails on the second publication.
                service(new ReportWriter(failOnMove(2))));

        assertEquals(ExitCode.REPORT_WRITE_ERROR, code);
        assertTrue(console.err().contains("could not be guaranteed"));
        assertTrue(console.err().contains("Inspect before trusting"));
        assertTrue(console.err().contains(destination.markdownPath().toString()));
        assertTrue(Files.exists(preserved), "the writer must not delete files it did not create");
        assertFalse(console.all().contains("\tat "), "no stack trace should reach the console");
    }

    // ---------- helpers ----------

    private static ReportWriter.FileMoveOperation failOnMove(int failingCall) {
        return new ReportWriter.FileMoveOperation() {
            private int calls;

            @Override
            public void move(Path source, Path target, CopyOption... options) throws IOException {
                if (++calls == failingCall) {
                    throw new IOException("synthetic publication failure");
                }
                Files.move(source, target, options);
            }
        };
    }
}
