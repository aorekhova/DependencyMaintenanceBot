package com.tungsten.depbot.remediation;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Renders a {@link RemediationPlan} as a human-readable Markdown document. */
public final class RemediationPlanMarkdownRenderer {

    static final String NOT_PROVIDED = "Not provided";
    static final String NO_LIBRARIES = "No libraries in this severity group.";

    public String render(RemediationPlan plan) {
        Objects.requireNonNull(plan, "plan");

        List<String> lines = new ArrayList<>();
        lines.add("# Mend Remediation Plan");
        lines.add("");
        lines.add("- Generated at: " + text(plan.generatedAt()));
        lines.add("- Source report generated at: " + text(plan.sourceReportGeneratedAt()));
        lines.add("- Report version: " + text(plan.reportVersion()));
        lines.add("");

        appendSection(lines, "Critical", plan.critical());
        appendSection(lines, "High", plan.high());
        appendSection(lines, "Medium", plan.medium());
        appendSection(lines, "Low", plan.low());
        appendSection(lines, "Manual analysis required", plan.manualAnalysisRequired());

        return String.join("\n", lines) + "\n";
    }

    private void appendSection(List<String> lines, String title, List<LibraryRemediation> entries) {
        String libraryWord = entries.size() == 1 ? "library" : "libraries";
        lines.add("## " + title + " (" + entries.size() + " " + libraryWord + ")");
        lines.add("");

        if (entries.isEmpty()) {
            lines.add(NO_LIBRARIES);
            lines.add("");
            return;
        }

        lines.add("| Library | Current version | Target version | CVEs |");
        lines.add("| --- | --- | --- | --- |");
        for (LibraryRemediation entry : entries) {
            lines.add("| " + cell(entry.coordinates())
                    + " | " + cell(entry.currentVersion())
                    + " | " + cell(entry.targetVersion())
                    + " | " + cell(String.join(", ", entry.vulnerabilityIds()))
                    + " |");
            if (entry.manualAnalysisReason() != null && !entry.manualAnalysisReason().isBlank()) {
                lines.add("  - Reason: " + cell(entry.manualAnalysisReason()));
            }
        }
        lines.add("");
    }

    private static String cell(String value) {
        if (value == null || value.isBlank()) {
            return NOT_PROVIDED;
        }
        return value.replace("|", "\\|").replace("\r\n", " ").replace("\n", " ").replace("\r", " ");
    }

    private static String text(String value) {
        return (value == null || value.isBlank()) ? NOT_PROVIDED : value;
    }
}
