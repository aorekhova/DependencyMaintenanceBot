package com.tungsten.depbot.run;

import java.nio.file.Path;
import java.util.Locale;

/**
 * Where one run's manifest, task files and attempt artifacts live under a given runs root --
 * normally {@code reports/runs/}, but injectable so tests never write outside a temporary directory.
 */
public final class RunPaths {

    private RunPaths() {
    }

    public static Path runDirectory(Path runsRoot, String runId) {
        return runsRoot.resolve(runId);
    }

    public static Path manifestPath(Path runsRoot, String runId) {
        return runDirectory(runsRoot, runId).resolve("run-manifest.json");
    }

    /** One file per unit, grouped by severity so a human can browse a run's work by priority. */
    public static Path taskFilePath(Path runsRoot, String runId, String severity, String groupId, String artifactId) {
        String fileName = sanitize(groupId) + "__" + sanitize(artifactId) + ".md";
        return runDirectory(runsRoot, runId)
                .resolve("tasks")
                .resolve(severity.toLowerCase(Locale.ROOT))
                .resolve(fileName);
    }

    /**
     * A unit's identity within its run. Includes the severity so that the same library appearing
     * under two severities (which the plan does not currently produce, but which would otherwise
     * silently overwrite one attempt with another) still gets its own directory.
     */
    public static String unitId(String severity, String groupId, String artifactId) {
        return sanitize(severity.toLowerCase(Locale.ROOT)) + "__" + sanitize(groupId) + "__" + sanitize(artifactId);
    }

    /**
     * The unit id a multi-member remediation group's implementation phase is filed under -- distinct
     * from any single library's own {@link #unitId}, since a group's implementation artifacts belong to
     * every member at once, not to one of them. A singleton group reuses {@link #unitId} instead, so the
     * common case of one unrelated finding is filed exactly where it always was.
     */
    public static String groupUnitId(String severity, String remediationGroupId) {
        return sanitize(severity.toLowerCase(Locale.ROOT)) + "__group__" + sanitize(remediationGroupId);
    }

    public static Path unitDirectory(Path runsRoot, String runId, String unitId) {
        return runDirectory(runsRoot, runId).resolve("units").resolve(unitId);
    }

    /** Attempts are numbered from 1 and never reused, so an earlier attempt is never overwritten. */
    public static Path attemptDirectory(Path runsRoot, String runId, String unitId, int attemptNumber) {
        return unitDirectory(runsRoot, runId, unitId).resolve("attempt-" + attemptNumber);
    }

    private static String sanitize(String value) {
        return value.replaceAll("[^A-Za-z0-9._-]", "_");
    }
}
