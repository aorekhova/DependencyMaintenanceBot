package com.tungsten.depbot.report.actionable;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Renders the report as Markdown for a human reader.
 *
 * <p>Two formatting decisions are about correctness rather than taste:
 *
 * <ul>
 *   <li><strong>Cell values are escaped.</strong> A {@code |} inside a value would split it into two
 *       columns and shift every cell after it, producing a table that looks plausible but shows the
 *       wrong data against the wrong labels. A newline would end the row outright. Both are
 *       neutralised in {@link #cell(String)}.</li>
 *   <li><strong>The two fields most likely to contain awkward text stay out of tables.</strong> The
 *       description goes in a paragraph block and file paths go in a bullet list, so their pipes and
 *       line breaks cannot damage any layout and their content survives intact.</li>
 * </ul>
 *
 * <p>Lines are joined with an explicit {@code "\n"} rather than the platform separator, so the file
 * is byte-identical wherever it is produced. All output is plain ASCII, because the Windows console
 * this tool targets reports a Cp1252 encoding and would mangle anything else.
 *
 * <p>The report passed in is expected to have been through {@link ActionableReportRedactor} already.
 */
public final class MarkdownReportRenderer {

    /** Shown wherever Mend supplied no value. Never a guess, never an empty cell. */
    static final String NOT_PROVIDED = "Not provided";

    static final String NO_FINDINGS = "No vulnerabilities were found in this scan.";

    private static final String TABLE_DIVIDER_TWO = "| --- | --- |";

    public String render(ActionableReport report) {
        Objects.requireNonNull(report, "report");

        List<String> lines = new ArrayList<>();
        appendHeader(lines, report);
        appendSummary(lines, report.summary());
        appendFindings(lines, report);

        return String.join("\n", lines) + "\n";
    }

    // ---------- header and summary ----------

    private void appendHeader(List<String> lines, ActionableReport report) {
        lines.add("# Mend Actionable Vulnerability Report");
        lines.add("");
        lines.add("- Generated at: " + text(report.generatedAt()));
        lines.add("- Report version: " + text(report.reportVersion()));
        lines.add("");
    }

    private void appendSummary(List<String> lines, ActionableSummary summary) {
        lines.add("## Summary");
        lines.add("");
        lines.add("| Severity | Count |");
        lines.add(TABLE_DIVIDER_TWO);
        lines.add(row("Critical", summary.criticalCount()));
        lines.add(row("High", summary.highCount()));
        lines.add(row("Medium", summary.mediumCount()));
        lines.add(row("Low", summary.lowCount()));
        lines.add(row("Other", summary.otherCount()));
        lines.add("| **Total** | **" + summary.totalVulnerabilities() + "** |");
        lines.add("");
        lines.add("All findings detailed below: " + summary.actionableCount());
        lines.add("");
    }

    // ---------- findings ----------

    private void appendFindings(List<String> lines, ActionableReport report) {
        lines.add("## Findings");
        lines.add("");

        if (!report.hasActionableFindings()) {
            lines.add(NO_FINDINGS);
            return;
        }

        int position = 1;
        for (ActionableFinding finding : report.findings()) {
            appendFinding(lines, position++, finding);
        }
    }

    private void appendFinding(List<String> lines, int position, ActionableFinding finding) {
        lines.add("### " + position + ". " + text(finding.vulnerabilityId())
                + " - " + text(finding.severity()));
        lines.add("");

        lines.add("| Field | Value |");
        lines.add(TABLE_DIVIDER_TWO);
        lines.add(row("Vulnerability ID", finding.vulnerabilityId()));
        lines.add(row("Type", finding.type()));
        lines.add(row("Severity", finding.severity()));
        lines.add(row("CVSS 3 severity", finding.cvss3Severity()));
        lines.add(row("CVSS 3 score", finding.cvss3Score()));
        lines.add(row("Mend score", finding.score()));
        lines.add(row("Score vector", finding.scoreMetadataVector()));
        lines.add(row("Published", finding.publishedDate()));
        lines.add(row("Last updated", finding.lastUpdatedDate()));
        lines.add(row("Reference", finding.referenceUrl()));
        lines.add(row("Product", finding.product()));
        lines.add(row("Project", finding.project()));
        lines.add("");

        appendLibrary(lines, finding.library());
        appendLocations(lines, finding.locations());
        appendRemediation(lines, finding.remediation());
        appendDescription(lines, finding.description());
    }

    private void appendLibrary(List<String> lines, AffectedLibrary library) {
        lines.add("#### Affected library");
        lines.add("");

        if (library == null) {
            lines.add(NOT_PROVIDED);
            lines.add("");
            return;
        }

        lines.add("| Field | Value |");
        lines.add(TABLE_DIVIDER_TWO);
        lines.add(row("Coordinates", library.coordinates()));
        lines.add(row("Group ID", library.groupId()));
        lines.add(row("Artifact ID", library.artifactId()));
        lines.add(row("Version", library.version()));
        lines.add(row("Name", library.name()));
        lines.add(row("Filename", library.filename()));
        lines.add(row("Type", library.type()));
        lines.add(row("SHA-1", library.sha1()));
        lines.add("");
    }

    /**
     * Paths go in a bullet list rather than a table cell: a path may contain a pipe, and a bullet
     * has no columns to damage.
     */
    private void appendLocations(List<String> lines, List<FindingLocation> locations) {
        lines.add("#### Locations");
        lines.add("");

        if (locations == null || locations.isEmpty()) {
            lines.add(NOT_PROVIDED);
            lines.add("");
            return;
        }

        for (FindingLocation location : locations) {
            String path = isBlank(location.path()) ? NOT_PROVIDED : location.path();
            String matchType = isBlank(location.matchType())
                    ? NOT_PROVIDED
                    : location.matchType();
            lines.add("- `" + path + "` (match type: " + matchType + ")");
        }
        lines.add("");
    }

    private void appendRemediation(List<String> lines, Remediation remediation) {
        lines.add("#### Recommended remediation");
        lines.add("");

        if (remediation == null || !remediation.hasAnyFix()) {
            lines.add(NOT_PROVIDED);
            lines.add("");
            return;
        }

        lines.add("**Top fix**");
        lines.add("");
        if (remediation.topFix() == null) {
            lines.add(NOT_PROVIDED);
            lines.add("");
        } else {
            appendFixTable(lines, remediation.topFix());
        }

        lines.add("**All fixes (" + remediation.allFixes().size() + ")**");
        lines.add("");
        if (remediation.allFixes().isEmpty()) {
            lines.add(NOT_PROVIDED);
            lines.add("");
            return;
        }

        lines.add("| # | Type | Fix resolution | Origin | URL | Date | Message |");
        lines.add("| --- | --- | --- | --- | --- | --- | --- |");
        int position = 1;
        for (RecommendedFix fix : remediation.allFixes()) {
            lines.add("| " + position++
                    + " | " + cell(fix.type())
                    + " | " + cell(fix.fixResolution())
                    + " | " + cell(fix.origin())
                    + " | " + cell(fix.url())
                    + " | " + cell(fix.date())
                    + " | " + cell(fix.message())
                    + " |");
        }
        lines.add("");
    }

    private void appendFixTable(List<String> lines, RecommendedFix fix) {
        lines.add("| Field | Value |");
        lines.add(TABLE_DIVIDER_TWO);
        lines.add(row("Fix resolution", fix.fixResolution()));
        lines.add(row("Type", fix.type()));
        lines.add(row("Origin", fix.origin()));
        lines.add(row("URL", fix.url()));
        lines.add(row("Date", fix.date()));
        lines.add(row("Message", fix.message()));
        lines.add(row("Vulnerability", fix.vulnerability()));
        lines.add("");
    }

    /**
     * The description is deliberately a paragraph block, not a table cell: it is the field most
     * likely to contain pipes and line breaks, and here they can be preserved verbatim instead of
     * being escaped or flattened.
     */
    private void appendDescription(List<String> lines, String description) {
        lines.add("#### Description");
        lines.add("");
        lines.add(isBlank(description) ? NOT_PROVIDED : description);
        lines.add("");
    }

    // ---------- cell helpers ----------

    private static String row(String label, String value) {
        return "| " + label + " | " + cell(value) + " |";
    }

    private static String row(String label, int value) {
        return "| " + label + " | " + value + " |";
    }

    /**
     * Makes a value safe to place inside a table cell. A pipe is escaped so it cannot be read as a
     * column separator, and line breaks become spaces so they cannot end the row early.
     */
    static String cell(String value) {
        if (isBlank(value)) {
            return NOT_PROVIDED;
        }
        return value
                .replace("|", "\\|")
                .replace("\r\n", " ")
                .replace("\n", " ")
                .replace("\r", " ");
    }

    private static String text(String value) {
        return isBlank(value) ? NOT_PROVIDED : value;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
