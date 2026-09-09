package com.tungsten.depbot.remediation;

import com.tungsten.depbot.cli.ExitCode;
import com.tungsten.depbot.report.ConsoleReporter;
import com.tungsten.depbot.report.actionable.ActionableFinding;
import com.tungsten.depbot.report.actionable.ActionableReport;
import com.tungsten.depbot.report.actionable.ActionableSummary;
import com.tungsten.depbot.report.actionable.AffectedLibrary;
import com.tungsten.depbot.report.actionable.JsonReportRenderer;
import com.tungsten.depbot.report.actionable.ReportDestination;
import com.tungsten.depbot.report.actionable.Remediation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemediationPlanCommandTest {

    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-08-04T10:00:00Z"), ZoneOffset.UTC);

    @TempDir
    Path dir;

    private final ByteArrayOutputStream outBuffer = new ByteArrayOutputStream();
    private final ByteArrayOutputStream errBuffer = new ByteArrayOutputStream();
    private final ConsoleReporter reporter = new ConsoleReporter(
            new PrintStream(outBuffer, true, StandardCharsets.UTF_8),
            new PrintStream(errBuffer, true, StandardCharsets.UTF_8));

    private String out() {
        return outBuffer.toString(StandardCharsets.UTF_8);
    }

    private String err() {
        return errBuffer.toString(StandardCharsets.UTF_8);
    }

    private ReportDestination sourceDestination() {
        return ReportDestination.into(dir);
    }

    private ReportDestination planDestination() {
        return new ReportDestination(dir,
                ReportDestination.REMEDIATION_PLAN_JSON_FILE_NAME,
                ReportDestination.REMEDIATION_PLAN_MARKDOWN_FILE_NAME);
    }

    private RemediationPlanCommand command() {
        RemediationPlanService service =
                new RemediationPlanService(FIXED_CLOCK, sourceDestination(), planDestination());
        return new RemediationPlanCommand(service, reporter);
    }

    private void writeSourceReport() throws IOException {
        AffectedLibrary library = new AffectedLibrary(
                "org.bouncycastle", "bcprov-jdk18on", "1.84", "org.bouncycastle:bcprov-jdk18on:1.84",
                "bcprov-jdk18on", "bcprov-jdk18on-1.84.jar", "JAVA", null, null, null, null, null);
        ActionableFinding finding = new ActionableFinding("CVE-2026-1", "CVE", "critical", null, null, null,
                null, null, null, null, null, null, null, null, library, List.of(), Remediation.empty());
        ActionableReport report = new ActionableReport("2026-08-04T09:00:00Z", "1.1",
                new ActionableSummary(1, 1, 0, 0, 0, 0, 1), List.of(finding));

        Files.writeString(sourceDestination().jsonPath(), new JsonReportRenderer().render(report),
                StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("a missing source report returns REMEDIATION_SOURCE_ERROR and explains why on stderr")
    void missingSourceReportReturnsSourceError() {
        assertEquals(ExitCode.REMEDIATION_SOURCE_ERROR, command().run());
        assertTrue(err().contains("Remediation plan error:"));
        assertEquals("", out());
    }

    @Test
    @DisplayName("a successful run prints the bucket summary and file locations, then returns SUCCESS")
    void successfulRunPrintsSummaryAndLocations() throws IOException {
        writeSourceReport();

        assertEquals(ExitCode.SUCCESS, command().run());
        assertTrue(out().contains("Remediation plan generated"));
        assertTrue(out().contains("Critical libraries: 1"));
        assertTrue(out().contains("remediation-plan.json"));
        assertTrue(out().contains("remediation-plan.md"));
        assertTrue(Files.exists(planDestination().jsonPath()));
        assertTrue(Files.exists(planDestination().markdownPath()));
    }
}
