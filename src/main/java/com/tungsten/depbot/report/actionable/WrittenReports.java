package com.tungsten.depbot.report.actionable;

import java.nio.file.Path;

/**
 * The two files a successful publication produced.
 *
 * <p>Returned so the console can tell the operator exactly what was written, rather than restating
 * paths it assumes were used.
 */
public record WrittenReports(Path jsonPath, Path markdownPath) {
}
