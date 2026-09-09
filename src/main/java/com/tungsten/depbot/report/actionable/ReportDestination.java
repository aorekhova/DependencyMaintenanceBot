package com.tungsten.depbot.report.actionable;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;

/**
 * Where the report pair is written.
 *
 * <p>The filenames are fixed rather than timestamped, so automation can read a known path. That
 * makes {@code generatedAt} inside the document the only marker of which run produced it, and it is
 * why {@link ReportWriter} invalidates the previous pair before every scan — otherwise a stale file
 * at a known name is indistinguishable from a fresh one.
 *
 * <p>Temporary files deliberately sit in the same directory as their targets. An atomic move only
 * works within one filesystem, so a temporary written to the system temp directory could not be
 * published atomically.
 */
public record ReportDestination(Path directory, String jsonFileName, String markdownFileName) {

    public static final String DEFAULT_DIRECTORY = "reports";
    public static final String DEFAULT_JSON_FILE_NAME = "mend-actionable-vulnerabilities.json";
    public static final String DEFAULT_MARKDOWN_FILE_NAME = "mend-actionable-vulnerabilities.md";
    public static final String REMEDIATION_PLAN_JSON_FILE_NAME = "remediation-plan.json";
    public static final String REMEDIATION_PLAN_MARKDOWN_FILE_NAME = "remediation-plan.md";

    private static final String TEMP_SUFFIX = ".tmp";

    public ReportDestination {
        Objects.requireNonNull(directory, "directory");
        requireUsableName(jsonFileName, "jsonFileName");
        requireUsableName(markdownFileName, "markdownFileName");
    }

    /** The production destination: {@code reports/} beside the working directory. */
    public static ReportDestination defaultDestination() {
        return new ReportDestination(
                Paths.get(DEFAULT_DIRECTORY),
                DEFAULT_JSON_FILE_NAME,
                DEFAULT_MARKDOWN_FILE_NAME);
    }

    /** The same filenames in a chosen directory. Tests use this with a temporary directory. */
    public static ReportDestination into(Path directory) {
        return new ReportDestination(directory, DEFAULT_JSON_FILE_NAME, DEFAULT_MARKDOWN_FILE_NAME);
    }

    /** Where {@code plan-remediation} writes its output, in the same directory as the scan report. */
    public static ReportDestination remediationPlanDestination() {
        return new ReportDestination(
                Paths.get(DEFAULT_DIRECTORY),
                REMEDIATION_PLAN_JSON_FILE_NAME,
                REMEDIATION_PLAN_MARKDOWN_FILE_NAME);
    }

    public Path jsonPath() {
        return directory.resolve(jsonFileName);
    }

    public Path markdownPath() {
        return directory.resolve(markdownFileName);
    }

    public Path jsonTempPath() {
        return directory.resolve(jsonFileName + TEMP_SUFFIX);
    }

    public Path markdownTempPath() {
        return directory.resolve(markdownFileName + TEMP_SUFFIX);
    }

    private static void requireUsableName(String name, String field) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
