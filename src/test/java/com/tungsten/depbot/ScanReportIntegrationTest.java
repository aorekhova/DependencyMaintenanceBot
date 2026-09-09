package com.tungsten.depbot;

import com.sun.net.httpserver.HttpServer;
import com.tungsten.depbot.cli.ExitCode;
import com.tungsten.depbot.config.EnvConfig;
import com.tungsten.depbot.mend.MendClient;
import com.tungsten.depbot.mend.MendGateway;
import com.tungsten.depbot.mend.model.VulnerabilityRecord;
import com.tungsten.depbot.mend.model.VulnerabilityReport;
import com.tungsten.depbot.report.actionable.ActionableReportService;
import com.tungsten.depbot.report.actionable.ReportDestination;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives a whole scan through {@link Main#run} and checks the console and the two report files
 * together, since the business requirement is that one scan produces both outputs consistently.
 */
class ScanReportIntegrationTest {

    private static final String USER_KEY = "USERKEY-DO-NOT-LEAK-9f3a";
    private static final String TOKEN = "TOKEN-DO-NOT-LEAK-7b1c";
    private static final EnvConfig CONFIG = new EnvConfig(USER_KEY, TOKEN);
    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-01-02T03:04:05Z"), ZoneOffset.UTC);

    private static final String PATH = "/api/v1.4";

    @TempDir
    Path reportDir;

    private HttpServer server;
    private HttpClient httpClient;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
        if (httpClient != null) {
            httpClient.close();
            httpClient = null;
        }
    }

    private ReportDestination destination() {
        return ReportDestination.into(reportDir);
    }

    private ActionableReportService reportService() {
        return new ActionableReportService(FIXED_CLOCK, destination());
    }

    private ExitCode scan(CapturedConsole console, MendGateway gateway) {
        return Main.run(new String[]{"scan"}, () -> CONFIG, gateway, console.reporter(),
                reportService());
    }

    private static MendGateway returning(String... severities) {
        List<VulnerabilityRecord> records = List.of(severities).stream()
                .map(VulnerabilityRecord::new)
                .toList();
        return config -> new VulnerabilityReport(records);
    }

    private String json() throws IOException {
        return Files.readString(destination().jsonPath(), StandardCharsets.UTF_8);
    }

    private String markdown() throws IOException {
        return Files.readString(destination().markdownPath(), StandardCharsets.UTF_8);
    }

    // ---------- one scan, two outputs ----------

    @Test
    @DisplayName("a successful scan writes both files and exits SUCCESS")
    void successfulScanWritesBothFiles() {
        CapturedConsole console = new CapturedConsole();

        assertEquals(ExitCode.SUCCESS, scan(console, returning("critical", "high", "medium")));

        assertTrue(Files.exists(destination().jsonPath()));
        assertTrue(Files.exists(destination().markdownPath()));
    }

    @Test
    @DisplayName("the console prints the summary and both report paths, and nothing else")
    void consolePrintsSummaryAndPaths() {
        CapturedConsole console = new CapturedConsole();

        scan(console, returning("critical", "high", "medium"));

        String out = console.out();
        assertTrue(out.contains("Mend vulnerability check completed"));
        assertTrue(out.contains("Total vulnerabilities: 3"));
        assertTrue(out.contains("Security result: VULNERABILITIES FOUND"));
        assertTrue(out.contains("Detailed report (JSON): "));
        assertTrue(out.contains("Detailed report (Markdown): "));
        assertTrue(out.contains(destination().jsonPath().toString()));
        assertTrue(out.contains(destination().markdownPath().toString()));
        assertEquals("", console.err(), "a successful scan should write nothing to stderr");
    }

    @Test
    @DisplayName("the console never prints a full vulnerability description")
    void consoleOmitsDescriptions() throws IOException {
        CapturedConsole console = new CapturedConsole();
        List<VulnerabilityRecord> vulnerabilities = new com.tungsten.depbot.mend
                .MendResponseParser()
                .parse(Fixtures.load("actionable-full-detail.json")).vulnerabilities();

        Main.run(new String[]{"scan"}, () -> CONFIG,
                config -> new VulnerabilityReport(vulnerabilities), console.reporter(),
                reportService());

        assertFalse(console.all().contains("Synthetic finding used only for automated tests"),
                "descriptions belong in the report files, not on the console");
        assertTrue(markdown().contains("Synthetic finding used only for automated tests"),
                "the description should still reach the Markdown report");
    }

    // ---------- selection versus summary ----------

    @Test
    @DisplayName("the summary and the findings agree: every severity is present in both")
    void summaryAndFindingsAgreeOnEverySeverity() throws IOException {
        CapturedConsole console = new CapturedConsole();

        scan(console, returning("critical", "high", "medium", "low"));

        assertTrue(console.out().contains("Total vulnerabilities: 4"));
        assertTrue(console.out().contains("Medium: 1"));

        assertTrue(json().contains("\"totalVulnerabilities\" : 4"));
        assertTrue(json().contains("\"mediumCount\" : 1"));
        assertTrue(json().contains("\"lowCount\" : 1"));
        assertTrue(json().contains("\"actionableCount\" : 4"));
        assertEquals(4, markdown().lines().filter(line -> line.startsWith("### ")).count());
    }

    @Test
    @DisplayName("both files hold the same number of findings, in the same order")
    void bothFilesAgreeOnFindings() throws IOException {
        CapturedConsole console = new CapturedConsole();
        List<VulnerabilityRecord> vulnerabilities = new com.tungsten.depbot.mend
                .MendResponseParser()
                .parse(Fixtures.load("actionable-multiple-fixes.json")).vulnerabilities();

        Main.run(new String[]{"scan"}, () -> CONFIG,
                config -> new VulnerabilityReport(vulnerabilities), console.reporter(),
                reportService());

        long jsonFindings = json().lines()
                .filter(line -> line.contains("\"vulnerabilityId\" :")).count();
        List<String> markdownHeadings = markdown().lines()
                .filter(line -> line.startsWith("### ")).toList();

        assertEquals(3, jsonFindings);
        assertEquals(3, markdownHeadings.size());
        // Same order: critical first, then the two high findings by id.
        assertTrue(markdownHeadings.get(0).contains("FAKE-CVE-0000-0801"));
        assertTrue(json().indexOf("FAKE-CVE-0000-0801") < json().indexOf("FAKE-CVE-0000-0802"));
    }

    @Test
    @DisplayName("a scan with only medium/low still writes both files with those findings listed")
    void mediumAndLowScanStillWritesFindings() throws IOException {
        CapturedConsole console = new CapturedConsole();

        assertEquals(ExitCode.SUCCESS, scan(console, returning("medium", "low")));

        assertTrue(console.out().contains("Security result: VULNERABILITIES FOUND"),
                "medium findings still count as vulnerabilities for the summary verdict");
        assertFalse(json().contains("\"findings\" : [ ]"),
                "medium/low findings must be listed, not filtered out");
        assertEquals(2, markdown().lines().filter(line -> line.startsWith("### ")).count());
    }

    @Test
    @DisplayName("a completely clean scan writes both files and says so twice")
    void cleanScanWritesBoth() throws IOException {
        CapturedConsole console = new CapturedConsole();

        assertEquals(ExitCode.SUCCESS,
                scan(console, config -> new VulnerabilityReport(List.of())));

        assertTrue(console.out().contains("Security result: NO VULNERABILITIES FOUND"));
        assertTrue(json().contains("\"totalVulnerabilities\" : 0"));
        assertTrue(markdown().contains("No vulnerabilities were found in this scan."));
    }

    // ---------- credentials ----------

    @Test
    @DisplayName("no credential reaches the console or either report file")
    void noCredentialAnywhere() throws IOException {
        CapturedConsole console = new CapturedConsole();
        List<VulnerabilityRecord> vulnerabilities = new com.tungsten.depbot.mend
                .MendResponseParser()
                .parse(Fixtures.load("actionable-hostile-text.json")).vulnerabilities();

        Main.run(new String[]{"scan"}, () -> CONFIG,
                config -> new VulnerabilityReport(vulnerabilities), console.reporter(),
                reportService());

        for (String text : List.of(console.all(), json(), markdown())) {
            assertFalse(text.contains(USER_KEY), "user key leaked");
            assertFalse(text.contains(TOKEN), "project token leaked");
        }
    }

    // ---------- end to end over HTTP ----------

    @Test
    @DisplayName("a scan over a real socket produces both files")
    void endToEndOverHttp() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(PATH, exchange -> {
            byte[] body = Fixtures.load("actionable-full-detail.json")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        MendClient client = new MendClient(httpClient,
                "http://127.0.0.1:" + server.getAddress().getPort() + PATH,
                Duration.ofSeconds(5));

        CapturedConsole console = new CapturedConsole();
        ExitCode code = Main.run(new String[]{"scan"}, () -> CONFIG, client, console.reporter(),
                reportService());

        assertEquals(ExitCode.SUCCESS, code);
        assertTrue(console.out().contains("Total vulnerabilities: 1"));
        assertTrue(json().contains("FAKE-CVE-0000-0101"));
        assertTrue(markdown().contains("### 1. FAKE-CVE-0000-0101 - HIGH"));
        assertTrue(markdown().contains("com.example.fake:example-fake-lib-core:1.0.1"),
                "the remediation a developer acts on should be present");
    }
}
