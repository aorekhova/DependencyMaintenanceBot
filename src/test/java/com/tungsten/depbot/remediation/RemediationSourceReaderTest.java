package com.tungsten.depbot.remediation;

import com.tungsten.depbot.report.actionable.ActionableReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemediationSourceReaderTest {

    @TempDir
    Path tempDir;

    private RemediationSourceReader reader() {
        return new RemediationSourceReader(
                tempDir.resolve("mend-actionable-vulnerabilities.json"),
                tempDir.resolve("remediation-plan.json"));
    }

    private void write(String name, String content) throws IOException {
        Files.writeString(tempDir.resolve(name), content, StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("both published documents are read back")
    void bothDocumentsAreReadBack() throws Exception {
        write("mend-actionable-vulnerabilities.json", """
                {"generatedAt":"2026-08-10T09:00:00Z","reportVersion":"1.1",
                 "summary":{"totalVulnerabilities":1,"criticalCount":1,"highCount":0,"mediumCount":0,
                            "lowCount":0,"otherCount":0,"actionableCount":1},
                 "findings":[{"vulnerabilityId":"CVE-1","severity":"critical",
                              "library":{"groupId":"g","artifactId":"a","version":"1.0"}}]}
                """);
        write("remediation-plan.json", """
                {"generatedAt":"2026-08-10T09:05:00Z","sourceReportGeneratedAt":"2026-08-10T09:00:00Z",
                 "reportVersion":"1.0","critical":[{"groupId":"g","artifactId":"a","currentVersion":"1.0",
                 "targetVersion":"2.0","maxSeverity":"CRITICAL","vulnerabilityIds":["CVE-1"]}],
                 "high":[],"medium":[],"low":[],"manualAnalysisRequired":[]}
                """);

        ActionableReport report = reader().readActionableReport();
        RemediationPlan plan = reader().readPlan();

        assertEquals(1, report.findings().size());
        assertEquals("CVE-1", report.findings().get(0).vulnerabilityId());
        assertEquals(1, plan.critical().size());
        assertEquals("2.0", plan.critical().get(0).targetVersion());
    }

    @Test
    @DisplayName("a missing document names the command that produces it")
    void missingDocumentNamesItsProducer() {
        RemediationSourceException scanMissing =
                assertThrows(RemediationSourceException.class, () -> reader().readActionableReport());
        assertTrue(scanMissing.getMessage().contains("scan"), scanMissing.getMessage());

        RemediationSourceException planMissing =
                assertThrows(RemediationSourceException.class, () -> reader().readPlan());
        assertTrue(planMissing.getMessage().contains("plan-remediation"), planMissing.getMessage());
    }

    @Test
    @DisplayName("a document that cannot be parsed is rejected rather than read as empty")
    void unparseableDocumentIsRejected() throws Exception {
        write("mend-actionable-vulnerabilities.json", "<html>not a report</html>");

        RemediationSourceException thrown =
                assertThrows(RemediationSourceException.class, () -> reader().readActionableReport());

        assertTrue(thrown.getMessage().contains("actionable report"), thrown.getMessage());
    }
}
