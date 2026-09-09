package com.tungsten.depbot.remediation;

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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemediationPlanServiceTest {

    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-08-04T10:00:00Z"), ZoneOffset.UTC);

    @TempDir
    Path dir;

    private ReportDestination sourceDestination() {
        return ReportDestination.into(dir);
    }

    private ReportDestination planDestination() {
        return new ReportDestination(dir,
                ReportDestination.REMEDIATION_PLAN_JSON_FILE_NAME,
                ReportDestination.REMEDIATION_PLAN_MARKDOWN_FILE_NAME);
    }

    private RemediationPlanService service() {
        return new RemediationPlanService(FIXED_CLOCK, sourceDestination(), planDestination());
    }

    private void writeSourceReport(ActionableReport report) throws IOException {
        String json = new JsonReportRenderer().render(report);
        Files.writeString(sourceDestination().jsonPath(), json, StandardCharsets.UTF_8);
    }

    private static ActionableReport sampleSourceReport() {
        AffectedLibrary library = new AffectedLibrary(
                "org.bouncycastle", "bcprov-jdk18on", "1.84", "org.bouncycastle:bcprov-jdk18on:1.84",
                "bcprov-jdk18on", "bcprov-jdk18on-1.84.jar", "JAVA", null, null, null, null, null);
        ActionableFinding finding = new ActionableFinding("CVE-2026-1", "CVE", "critical", null, null, null,
                null, null, null, null, null, null, null, null, library, List.of(), Remediation.empty());
        return new ActionableReport("2026-08-04T09:00:00Z", "1.1",
                new ActionableSummary(1, 1, 0, 0, 0, 0, 1), List.of(finding));
    }

    @Test
    @DisplayName("a missing source report throws RemediationSourceException")
    void missingSourceReportThrows() {
        RemediationSourceException e = assertThrows(RemediationSourceException.class, () -> service().generate());
        assertTrue(e.getMessage().contains("scan"));
    }

    @Test
    @DisplayName("a malformed source report throws RemediationSourceException")
    void malformedSourceReportThrows() throws IOException {
        Files.writeString(sourceDestination().jsonPath(), "{ not valid json", StandardCharsets.UTF_8);

        assertThrows(RemediationSourceException.class, () -> service().generate());
    }

    @Test
    @DisplayName("a valid source report produces both plan files with the expected content")
    void happyPathWritesBothFiles() throws IOException {
        writeSourceReport(sampleSourceReport());

        RemediationPlanOutcome outcome = service().generate();

        assertEquals(1, outcome.plan().critical().size());
        assertTrue(Files.exists(planDestination().jsonPath()));
        assertTrue(Files.exists(planDestination().markdownPath()));
        assertTrue(Files.readString(planDestination().jsonPath()).contains("bcprov-jdk18on"));
        assertTrue(Files.readString(planDestination().markdownPath()).contains("bcprov-jdk18on"));
    }

    @Test
    @DisplayName("invalidatePreviousPlan removes a stale plan pair before a new one is generated")
    void invalidateRemovesStalePlan() throws IOException {
        writeSourceReport(sampleSourceReport());
        service().generate();
        assertTrue(Files.exists(planDestination().jsonPath()));

        RemediationPlanService service = service();
        service.invalidatePreviousPlan();
        assertTrue(Files.notExists(planDestination().jsonPath()));
        assertTrue(Files.notExists(planDestination().markdownPath()));
    }

    @Test
    @DisplayName("invalidatePreviousPlan on an already-clean directory does not throw")
    void invalidateOnCleanDirectoryIsSafe() {
        assertDoesNotThrow(() -> service().invalidatePreviousPlan());
    }
}
