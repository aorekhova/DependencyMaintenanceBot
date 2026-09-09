package com.tungsten.depbot.report.actionable;

import com.tungsten.depbot.Fixtures;
import com.tungsten.depbot.mend.MendResponseParser;
import com.tungsten.depbot.mend.model.VulnerabilityRecord;
import com.tungsten.depbot.report.SecretRedactor;
import com.tungsten.depbot.report.SeverityCounts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MarkdownReportRendererTest {

    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-01-02T03:04:05Z"), ZoneOffset.UTC);

    private final MarkdownReportRenderer renderer = new MarkdownReportRenderer();

    // ---------- helpers ----------

    private static ActionableReport reportFrom(String fixture) {
        List<VulnerabilityRecord> vulnerabilities = new MendResponseParser()
                .parse(Fixtures.load(fixture)).vulnerabilities();
        return new ActionableReportFactory(FIXED_CLOCK)
                .build(vulnerabilities, SeverityCounts.from(vulnerabilities));
    }

    private static ActionableReport emptyReport() {
        return ActionableReport.of("2026-01-02T03:04:05Z",
                new ActionableSummary(3, 0, 0, 2, 1, 0, 0), List.of());
    }

    /** Every line that looks like a table row, for structural checks. */
    private static List<String> tableRows(String markdown) {
        return markdown.lines()
                .filter(line -> line.startsWith("|"))
                .toList();
    }

    // ---------- header and summary ----------

    @Test
    @DisplayName("the header carries the generation time and schema version")
    void headerCarriesMetadata() {
        String markdown = renderer.render(reportFrom("actionable-full-detail.json"));

        assertTrue(markdown.startsWith("# Mend Actionable Vulnerability Report"));
        assertTrue(markdown.contains("- Generated at: 2026-01-02T03:04:05Z"));
        assertTrue(markdown.contains("- Report version: 1.1"));
    }

    @Test
    @DisplayName("the summary lists all six severity buckets plus a bold total")
    void summaryListsEveryBucket() {
        String markdown = renderer.render(reportFrom("success-mixed-severities.json"));

        // The fixture holds 1 critical, 2 high, 1 medium, 1 low and 1 unrecognised.
        assertTrue(markdown.contains("| Critical | 1 |"));
        assertTrue(markdown.contains("| High | 2 |"));
        assertTrue(markdown.contains("| Medium | 1 |"));
        assertTrue(markdown.contains("| Low | 1 |"));
        assertTrue(markdown.contains("| Other | 1 |"));
        assertTrue(markdown.contains("| **Total** | **6** |"));
    }

    @Test
    @DisplayName("the findings count is stated and covers every severity")
    void actionableCountStated() {
        assertTrue(renderer.render(reportFrom("success-mixed-severities.json"))
                .contains("All findings detailed below: 6"));
    }

    @Test
    @DisplayName("every severity gets its own section, not just critical and high")
    void everySeverityHasASection() {
        String markdown = renderer.render(reportFrom("success-mixed-severities.json"));

        assertTrue(markdown.contains("| Medium | 1 |"));
        assertEquals(6, markdown.lines().filter(line -> line.startsWith("### ")).count(),
                "the fixture holds 6 entries across 5 severities; all must have a section");
    }

    // ---------- finding sections ----------

    @Test
    @DisplayName("there is one numbered section per finding, in report order")
    void oneSectionPerFinding() {
        String markdown = renderer.render(reportFrom("actionable-multiple-fixes.json"));

        List<String> headings = markdown.lines().filter(line -> line.startsWith("### ")).toList();

        assertEquals(3, headings.size());
        assertTrue(headings.get(0).startsWith("### 1. FAKE-CVE-0000-0801 - CRITICAL"));
        assertTrue(headings.get(1).startsWith("### 2. "));
        assertTrue(headings.get(2).startsWith("### 3. "));
    }

    @Test
    @DisplayName("the finding table shows every documented attribute")
    void findingTableShowsAllAttributes() {
        String markdown = renderer.render(reportFrom("actionable-full-detail.json"));

        assertTrue(markdown.contains("| Vulnerability ID | FAKE-CVE-0000-0101 |"));
        assertTrue(markdown.contains("| Type | SECURITY_VULNERABILITY |"));
        assertTrue(markdown.contains("| Severity | HIGH |"));
        assertTrue(markdown.contains("| CVSS 3 severity | high |"));
        assertTrue(markdown.contains("| CVSS 3 score | 8.1 |"));
        assertTrue(markdown.contains("| Published | 2020-01-15 |"));
        assertTrue(markdown.contains("| Last updated | 2020-06-30 |"));
        assertTrue(markdown.contains("| Reference | https://example.invalid/fake-advisory/0101 |"));
        assertTrue(markdown.contains("| Product | synthetic-test-product |"));
        assertTrue(markdown.contains("| Project | synthetic-test-project |"));
    }

    // ---------- library ----------

    @Test
    @DisplayName("a complete library shows coordinates and every part")
    void completeLibraryRendered() {
        String markdown = renderer.render(reportFrom("actionable-full-detail.json"));

        assertTrue(markdown.contains("#### Affected library"));
        assertTrue(markdown.contains(
                "| Coordinates | com.example.fake:example-fake-lib-core:1.0.0 |"));
        assertTrue(markdown.contains("| Group ID | com.example.fake |"));
        assertTrue(markdown.contains("| Artifact ID | example-fake-lib-core |"));
        assertTrue(markdown.contains("| Version | 1.0.0 |"));
        assertTrue(markdown.contains("| SHA-1 | 0000000000000000000000000000000000000101 |"));
    }

    @Test
    @DisplayName("a missing groupId shows Not provided for coordinates and group")
    void missingGroupIdShowsNotProvided() {
        String markdown = renderer.render(reportFrom("actionable-missing-coordinates.json"));

        assertTrue(markdown.contains("| Coordinates | " + MarkdownReportRenderer.NOT_PROVIDED + " |"),
                "coordinates must not be fabricated from partial data");
        assertTrue(markdown.contains("| Group ID | " + MarkdownReportRenderer.NOT_PROVIDED + " |"));
        assertTrue(markdown.contains("| Artifact ID | example-fake-nogroup |"),
                "the parts that are present should still be shown");
    }

    @Test
    @DisplayName("an absent library shows Not provided for the whole section")
    void absentLibraryShowsNotProvided() {
        String markdown = renderer.render(reportFrom("actionable-no-library.json"));

        int sectionStart = markdown.indexOf("#### Affected library");
        int nextSection = markdown.indexOf("#### Locations");

        assertTrue(sectionStart >= 0 && nextSection > sectionStart);
        assertTrue(markdown.substring(sectionStart, nextSection)
                        .contains(MarkdownReportRenderer.NOT_PROVIDED),
                "the library section should say so rather than showing an empty table");
    }

    // ---------- locations ----------

    @Test
    @DisplayName("multiple locations render as bullets with their match types")
    void multipleLocationsRendered() {
        String markdown = renderer.render(reportFrom("actionable-full-detail.json"));

        assertTrue(markdown.contains(
                "- `/synthetic/build/libs/example-fake-lib-core-1.0.0.jar` "
                        + "(match type: EXACT_MATCH)"));
        assertTrue(markdown.contains(
                "- `/synthetic/cache/example-fake-lib-core-1.0.0.jar` "
                        + "(match type: FILENAME_MATCH)"));
    }

    @Test
    @DisplayName("absent locations show Not provided")
    void absentLocationsShowNotProvided() {
        String markdown = renderer.render(reportFrom("actionable-no-locations.json"));

        int sectionStart = markdown.indexOf("#### Locations");
        int nextSection = markdown.indexOf("#### Recommended remediation");

        assertTrue(markdown.substring(sectionStart, nextSection)
                .contains(MarkdownReportRenderer.NOT_PROVIDED));
    }

    // ---------- remediation ----------

    @Test
    @DisplayName("the top fix shows every remediation field a developer acts on")
    void topFixShowsEveryField() {
        String markdown = renderer.render(reportFrom("actionable-multiple-fixes.json"));

        assertTrue(markdown.contains("#### Recommended remediation"));
        assertTrue(markdown.contains("**Top fix**"));
        assertTrue(markdown.contains(
                "| Fix resolution | com.example.fake:example-fake-multi:2.0.0 |"));
        assertTrue(markdown.contains("| Type | UPGRADE_VERSION |"));
        assertTrue(markdown.contains("| Origin | EXAMPLE_FAKE_ADVISORY |"));
        assertTrue(markdown.contains("| URL | https://example.invalid/fake-fix/0801-top |"));
        assertTrue(markdown.contains("| Date | 2021-03-04 |"));
        assertTrue(markdown.contains("| Message | Preferred synthetic remediation. |"));
    }

    @Test
    @DisplayName("every entry in allFixes is rendered")
    void allFixesRendered() {
        String markdown = renderer.render(reportFrom("actionable-multiple-fixes.json"));

        assertTrue(markdown.contains("**All fixes (3)**"));
        assertTrue(markdown.contains("Apply the synthetic patch bundle."));
        assertTrue(markdown.contains("WORKAROUND"),
                "a fix carrying only a type must still be listed");
    }

    @Test
    @DisplayName("a fix with missing optional fields shows Not provided per cell")
    void sparseFixShowsNotProvided() {
        String markdown = renderer.render(reportFrom("actionable-multiple-fixes.json"));

        // The third fix has only a type, so its remaining cells fall back.
        assertTrue(markdown.lines().anyMatch(line -> line.startsWith("| 3 | WORKAROUND |")
                        && line.contains(MarkdownReportRenderer.NOT_PROVIDED)),
                "expected the sparse fix row to fall back per cell");
    }

    @Test
    @DisplayName("an absent topFix says so while still listing allFixes")
    void absentTopFixStillListsAllFixes() {
        String markdown = renderer.render(reportFrom("actionable-multiple-fixes.json"));

        int second = markdown.indexOf("### 2. ");
        int third = markdown.indexOf("### 3. ");
        String secondSection = markdown.substring(second, third);

        assertTrue(secondSection.contains("**Top fix**"));
        assertTrue(secondSection.contains(MarkdownReportRenderer.NOT_PROVIDED));
        assertTrue(secondSection.contains("com.example.fake:example-fake-notop:1.0.1"));
    }

    @Test
    @DisplayName("no remediation at all shows Not provided")
    void noRemediationShowsNotProvided() {
        String markdown = renderer.render(reportFrom("actionable-multiple-fixes.json"));

        String thirdSection = markdown.substring(markdown.indexOf("### 3. "));
        int start = thirdSection.indexOf("#### Recommended remediation");
        int end = thirdSection.indexOf("#### Description");

        assertTrue(thirdSection.substring(start, end)
                .contains(MarkdownReportRenderer.NOT_PROVIDED));
    }

    // ---------- description ----------

    @Test
    @DisplayName("the description appears in a block, not inside a table cell")
    void descriptionIsABlock() {
        String markdown = renderer.render(reportFrom("actionable-full-detail.json"));

        assertTrue(markdown.contains("#### Description"));
        assertTrue(markdown.contains(
                "Synthetic finding used only for automated tests. Not a real vulnerability."));
    }

    @Test
    @DisplayName("a missing description shows Not provided")
    void missingDescriptionShowsNotProvided() {
        String markdown = renderer.render(reportFrom("actionable-minimal-fields.json"));

        String block = markdown.substring(markdown.indexOf("#### Description"));
        assertTrue(block.contains(MarkdownReportRenderer.NOT_PROVIDED));
    }

    // ---------- escaping ----------

    @Test
    @DisplayName("a pipe inside a cell value is escaped so the table structure survives")
    void pipeInCellIsEscaped() {
        // The hostile fixture puts a pipe in the library name, product and project.
        String markdown = renderer.render(reportFrom("actionable-hostile-text.json"));

        assertTrue(markdown.contains("\\|"), "expected an escaped pipe somewhere in a cell");

        // The property that matters is that every table stays rectangular: each row must have the
        // same number of unescaped pipes as its header. An unescaped pipe inside a cell would add
        // one, silently shifting every value after it into the wrong column.
        List<String> block = new ArrayList<>();
        for (String line : markdown.lines().toList()) {
            if (line.startsWith("|")) {
                block.add(line);
            } else {
                assertBlockIsRectangular(block);
                block = new ArrayList<>();
            }
        }
        assertBlockIsRectangular(block);
    }

    private static void assertBlockIsRectangular(List<String> block) {
        if (block.isEmpty()) {
            return;
        }
        long columns = countUnescapedPipes(block.get(0));
        for (String row : block) {
            assertEquals(columns, countUnescapedPipes(row),
                    "row does not match its table's column count, so a cell broke the "
                            + "structure: " + row);
        }
    }

    /** Counts pipes that are not preceded by a backslash. */
    private static long countUnescapedPipes(String row) {
        long count = 0;
        for (int i = 0; i < row.length(); i++) {
            if (row.charAt(i) == '|' && (i == 0 || row.charAt(i - 1) != '\\')) {
                count++;
            }
        }
        return count;
    }

    @Test
    @DisplayName("a newline inside a cell value is flattened so the row cannot break")
    void newlineInCellIsFlattened() {
        String markdown = renderer.render(reportFrom("actionable-hostile-text.json"));

        // The fixture's product contains a literal newline; as a cell it must occupy one line.
        assertTrue(markdown.lines().anyMatch(line ->
                        line.startsWith("| Product |") && line.endsWith("|")),
                "the product row should be a single complete line");
        assertTrue(markdown.contains("| Product | synthetic product |"),
                "the newline should have become a space");
    }

    @Test
    @DisplayName("the description keeps its pipes and line breaks verbatim in the block")
    void descriptionKeepsRawCharacters() {
        ActionableReport report = reportFrom("actionable-hostile-text.json");
        String markdown = renderer.render(report);

        String description = report.findings().get(0).description();
        assertTrue(description.contains("|") && description.contains("\n"));
        assertTrue(markdown.contains(description),
                "the description block should preserve the value exactly");
    }

    // ---------- empty result ----------

    @Test
    @DisplayName("no findings at all states so clearly and still shows the summary")
    void emptyResultIsExplicit() {
        String markdown = renderer.render(emptyReport());

        assertTrue(markdown.contains(MarkdownReportRenderer.NO_FINDINGS));
        assertTrue(markdown.contains("| Medium | 2 |"), "the summary must still be present");
        assertTrue(markdown.contains("| **Total** | **3** |"));
        assertTrue(markdown.contains("All findings detailed below: 0"));
        assertEquals(0, markdown.lines().filter(line -> line.startsWith("### ")).count());
    }

    @Test
    @DisplayName("a scan with nothing at all still produces a complete document")
    void completelyEmptyScanRenders() {
        String markdown = renderer.render(ActionableReport.of("2026-01-02T03:04:05Z",
                new ActionableSummary(0, 0, 0, 0, 0, 0, 0), List.of()));

        assertTrue(markdown.startsWith("# Mend Actionable Vulnerability Report"));
        assertTrue(markdown.contains("| **Total** | **0** |"));
        assertTrue(markdown.contains(MarkdownReportRenderer.NO_FINDINGS));
    }

    // ---------- output hygiene ----------

    @ParameterizedTest
    @ValueSource(strings = {
            "actionable-full-detail.json",
            "actionable-hostile-text.json",
            "actionable-multiple-fixes.json",
            "actionable-minimal-fields.json"
    })
    @DisplayName("the output contains no carriage return")
    void noCarriageReturn(String fixture) {
        assertFalse(renderer.render(reportFrom(fixture)).contains("\r"));
    }

    @Test
    @DisplayName("all output is plain ASCII")
    void outputIsAscii() {
        String markdown = renderer.render(reportFrom("actionable-hostile-text.json"));

        assertTrue(markdown.chars().allMatch(c -> c < 128 || c == '\n'),
                "a Cp1252 console would mangle non-ASCII output");
    }

    @Test
    @DisplayName("rendering the same report twice is byte-identical")
    void renderingIsDeterministic() {
        ActionableReport report = reportFrom("actionable-full-detail.json");

        assertEquals(renderer.render(report), renderer.render(report));
        assertEquals(new MarkdownReportRenderer().render(report), renderer.render(report));
    }

    @Test
    @DisplayName("the document ends with a single newline")
    void endsWithNewline() {
        String markdown = renderer.render(emptyReport());

        assertTrue(markdown.endsWith("\n"));
        assertFalse(markdown.endsWith("\n\n"));
    }

    // ---------- redaction, deferred from checkpoint 6 ----------

    @Test
    @DisplayName("secrets masked in the model do not appear in the Markdown")
    void redactedSecretsAbsentFromMarkdown() {
        String userKey = "USERKEY-DO-NOT-LEAK-9f3a";
        String token = "TOKEN-DO-NOT-LEAK-7b1c";

        ActionableReport redacted = ActionableReportRedactor
                .withSecrets(userKey, token)
                .redact(reportFrom("actionable-hostile-text.json"));

        String markdown = renderer.render(redacted);

        assertFalse(markdown.contains(userKey), "user key reached the Markdown report");
        assertFalse(markdown.contains(token), "project token reached the Markdown report");
        assertTrue(markdown.contains(SecretRedactor.MASK));
    }

    @ParameterizedTest
    @ValueSource(strings = {"SEC-quote\"inside-a1", "SEC-back\\slash-b2", "SEC-new\nline-c3"})
    @DisplayName("an awkwardly shaped secret does not survive into the Markdown")
    void awkwardSecretsAbsentFromMarkdown(String secret) {
        ActionableFinding finding = new ActionableFinding("FAKE-CVE-0000-0001", null, "HIGH", null,
                null, null, null, null, "leaks " + secret + " here", null, null, null,
                "product " + secret, null, null,
                List.of(new FindingLocation("/synthetic/" + secret, "EXACT_MATCH")), null);

        ActionableReport redacted = ActionableReportRedactor.withSecrets(secret)
                .redact(ActionableReport.of("2026-01-02T03:04:05Z",
                        new ActionableSummary(1, 0, 1, 0, 0, 0, 1), List.of(finding)));

        assertFalse(renderer.render(redacted).contains(secret));
    }

    // ---------- contract ----------

    @Test
    @DisplayName("a null report is rejected")
    void nullReportRejected() {
        assertThrows(NullPointerException.class, () -> renderer.render(null));
    }

    @Test
    @DisplayName("cell falls back for null and blank values")
    void cellFallsBack() {
        assertEquals(MarkdownReportRenderer.NOT_PROVIDED, MarkdownReportRenderer.cell(null));
        assertEquals(MarkdownReportRenderer.NOT_PROVIDED, MarkdownReportRenderer.cell(""));
        assertEquals(MarkdownReportRenderer.NOT_PROVIDED, MarkdownReportRenderer.cell("   "));
        assertEquals("plain", MarkdownReportRenderer.cell("plain"));
    }
}
