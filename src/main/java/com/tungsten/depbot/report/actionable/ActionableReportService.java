package com.tungsten.depbot.report.actionable;

import com.tungsten.depbot.mend.history.MendSnapshotHistoryService;
import com.tungsten.depbot.mend.model.VulnerabilityRecord;
import com.tungsten.depbot.report.SecretRedactor;
import com.tungsten.depbot.report.SeverityCounts;

import java.time.Clock;
import java.util.List;
import java.util.Objects;

/**
 * Produces the detailed report pair for one scan.
 *
 * <p>Composes the pipeline: build the report, mask credentials in the <em>model</em>, render both
 * representations, then publish them as a coordinated pair.
 *
 * <p>Redaction happens on the model rather than on rendered text because JSON escaping rewrites a
 * secret's characters — a credential containing a quote is written as {@code \"} — so a text-level
 * replace could not match it. A second pass over the rendered strings is kept as defence in depth;
 * in practice it finds nothing, which is the point.
 *
 * <p>Instances are immutable. {@link #withSecrets(String...)} derives a new service that masks the
 * given values, mirroring {@code ConsoleReporter.withSecrets} so there is one pattern to learn.
 */
public final class ActionableReportService {

    private final Clock clock;
    private final ActionableReportFactory factory;
    private final ReportDestination destination;
    private final ReportWriter writer;
    private final SecretRedactor secretRedactor;
    private final ActionableReportRedactor modelRedactor;
    private final JsonReportRenderer jsonRenderer = new JsonReportRenderer();
    private final MarkdownReportRenderer markdownRenderer = new MarkdownReportRenderer();
    private final MendSnapshotHistoryService historyService;

    /** The production service: a UTC clock and the real filesystem writer. */
    public ActionableReportService(Clock clock, ReportDestination destination) {
        this(clock, destination, new ReportWriter(), SecretRedactor.none());
    }

    /** Allows a test to supply a writer that fails in a controlled way. */
    public ActionableReportService(Clock clock, ReportDestination destination, ReportWriter writer) {
        this(clock, destination, writer, SecretRedactor.none());
    }

    private ActionableReportService(Clock clock,
                                    ReportDestination destination,
                                    ReportWriter writer,
                                    SecretRedactor secretRedactor) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.factory = new ActionableReportFactory(this.clock);
        this.destination = Objects.requireNonNull(destination, "destination");
        this.writer = Objects.requireNonNull(writer, "writer");
        this.secretRedactor = Objects.requireNonNull(secretRedactor, "secretRedactor");
        this.modelRedactor = new ActionableReportRedactor(secretRedactor);
        this.historyService = new MendSnapshotHistoryService(destination.directory().resolve("mend-history"));
    }

    /** Returns a new service that masks the given values in everything it writes. */
    public ActionableReportService withSecrets(String... secrets) {
        return new ActionableReportService(clock, destination, writer, SecretRedactor.of(secrets));
    }

    /**
     * Removes the previous report pair.
     *
     * <p>Called at the start of a scan so a run that later fails cannot leave a stale report looking
     * current. If this fails the scan must stop before contacting Mend, because the report contract
     * can no longer be guaranteed.
     *
     * @throws ReportWriteException if a previous file could not be removed
     */
    public void invalidatePreviousReports() {
        writer.invalidate(destination);
    }

    /**
     * Builds, redacts, renders and publishes the report pair.
     *
     * @param allVulnerabilities every entry Mend returned, at every severity
     * @param counts             the counts already computed for the console, so the two outputs
     *                           cannot disagree
     * @throws ReportWriteException if either file could not be written or published
     */
    public WrittenReports generate(List<VulnerabilityRecord> allVulnerabilities,
                                   SeverityCounts counts) {
        ActionableReport redacted = modelRedactor.redact(factory.build(allVulnerabilities, counts));

        // The fingerprint is computed -- and the snapshot persisted to history -- strictly after
        // redaction, never before: no persisted Mend-history content may ever bypass redaction.
        MendSnapshotHistoryService.MendSnapshotReference reference =
                historyService.record(redacted.findings(), clock.instant());
        ActionableReport report = redacted.withSourceSnapshotFingerprint(reference.fingerprint());

        String json = secretRedactor.redact(jsonRenderer.render(report));
        String markdown = secretRedactor.redact(markdownRenderer.render(report));

        return writer.publish(destination, json, markdown);
    }

    public ReportDestination destination() {
        return destination;
    }
}
