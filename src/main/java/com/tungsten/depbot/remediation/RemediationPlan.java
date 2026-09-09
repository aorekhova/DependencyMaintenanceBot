package com.tungsten.depbot.remediation;

import java.util.List;

/**
 * The output of {@code plan-remediation}: every library from the source actionable report,
 * grouped by its own maximum severity.
 *
 * <p>A library belongs to exactly one of {@link #critical()}, {@link #high()}, {@link #medium()}
 * or {@link #low()} when its maximum severity is unambiguously one of those four. A library whose
 * maximum severity is {@code OTHER} (Mend returned a severity this application does not recognise)
 * does not fit any of the four named buckets and is kept in {@link #manualAnalysisRequired()}
 * instead, so it is never silently dropped from the plan.
 *
 * <p>{@link #reportVersion()} starts its own numbering at {@value #CURRENT_VERSION}: this is a
 * different document type from the actionable report it is built from, not a revision of it.
 */
public record RemediationPlan(
        String generatedAt,
        String sourceReportGeneratedAt,
        String reportVersion,
        List<LibraryRemediation> critical,
        List<LibraryRemediation> high,
        List<LibraryRemediation> medium,
        List<LibraryRemediation> low,
        List<LibraryRemediation> manualAnalysisRequired,
        String sourceSnapshotFingerprint) {

    public static final String CURRENT_VERSION = "1.0";

    public RemediationPlan {
        reportVersion = (reportVersion == null || reportVersion.isBlank()) ? CURRENT_VERSION : reportVersion;
        critical = critical == null ? List.of() : List.copyOf(critical);
        high = high == null ? List.of() : List.copyOf(high);
        medium = medium == null ? List.of() : List.copyOf(medium);
        low = low == null ? List.of() : List.copyOf(low);
        manualAnalysisRequired = manualAnalysisRequired == null ? List.of() : List.copyOf(manualAnalysisRequired);
    }

    /**
     * Legacy 8-arg constructor kept for every existing caller: {@code sourceSnapshotFingerprint}
     * defaults to {@code null}, exactly as an old persisted plan (predating the Mend snapshot
     * history store) reads back today.
     */
    public RemediationPlan(
            String generatedAt,
            String sourceReportGeneratedAt,
            String reportVersion,
            List<LibraryRemediation> critical,
            List<LibraryRemediation> high,
            List<LibraryRemediation> medium,
            List<LibraryRemediation> low,
            List<LibraryRemediation> manualAnalysisRequired) {
        this(generatedAt, sourceReportGeneratedAt, reportVersion, critical, high, medium, low,
                manualAnalysisRequired, null);
    }

    public int totalLibraries() {
        return critical.size() + high.size() + medium.size() + low.size() + manualAnalysisRequired.size();
    }
}
