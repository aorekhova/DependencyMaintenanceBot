package com.tungsten.depbot.report.actionable;

import java.util.List;

/**
 * The detailed actionable vulnerability report, in the form it is published.
 *
 * <p>This is the contract that future Jenkins, GitLab and remediation automation reads. It is
 * deliberately a separate model from the Mend integration records: a change to Mend's response
 * should break a mapping function, not quietly alter the shape of a file other systems depend on.
 *
 * <p>The report filenames are fixed rather than timestamped, so {@code generatedAt} inside the
 * document is the only thing that identifies which run produced it. {@code reportVersion} lets a
 * consumer tell schema generations apart; adding it now costs nothing, whereas retrofitting it
 * later would force every consumer to handle its absence.
 *
 * <p>{@code findings} covers every severity Mend returned — Critical, High, Medium, Low and Other
 * alike — sorted with the most severe first; it is never {@code null} and always an immutable
 * copy. An empty list is a valid and meaningful result, saying that the scan ran and Mend returned
 * no vulnerabilities at all.
 *
 * <p>{@code sourceSnapshotFingerprint} is the canonical, order-independent, already-redacted-content
 * fingerprint (see {@code com.tungsten.depbot.mend.history.MendSnapshotFingerprint}) identifying the
 * exact Mend vulnerability snapshot this report was built from -- {@code null} for any report
 * written before the Mend snapshot history store existed, and for the {@link #of} convenience factory
 * until {@link #withSourceSnapshotFingerprint} is called once the snapshot has been recorded.
 */
public record ActionableReport(
        String generatedAt,
        String reportVersion,
        ActionableSummary summary,
        List<ActionableFinding> findings,
        String sourceSnapshotFingerprint) {

    /** The schema generation this application writes. */
    public static final String CURRENT_VERSION = "1.1";

    public ActionableReport {
        reportVersion = (reportVersion == null || reportVersion.isBlank())
                ? CURRENT_VERSION
                : reportVersion;
        findings = findings == null ? List.of() : List.copyOf(findings);
    }

    /**
     * Legacy 4-arg constructor kept for every existing caller: {@code sourceSnapshotFingerprint}
     * defaults to {@code null}, exactly as an old persisted report (predating the Mend snapshot
     * history store) reads back today.
     */
    public ActionableReport(String generatedAt, String reportVersion, ActionableSummary summary,
            List<ActionableFinding> findings) {
        this(generatedAt, reportVersion, summary, findings, null);
    }

    /** Builds a report stamped with the current schema version. */
    public static ActionableReport of(String generatedAt,
                                      ActionableSummary summary,
                                      List<ActionableFinding> findings) {
        return new ActionableReport(generatedAt, CURRENT_VERSION, summary, findings, null);
    }

    /** True when the report details at least one finding, at any severity. */
    public boolean hasActionableFindings() {
        return !findings.isEmpty();
    }

    /** Returns a copy carrying the Mend snapshot fingerprint this report was built from. */
    public ActionableReport withSourceSnapshotFingerprint(String fingerprint) {
        return new ActionableReport(generatedAt, reportVersion, summary, findings, fingerprint);
    }
}
