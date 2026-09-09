package com.tungsten.depbot.report.actionable;

import com.tungsten.depbot.mend.model.VulnerabilityRecord;
import com.tungsten.depbot.report.SeverityCounts;

import java.time.Clock;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;

/**
 * Assembles the finished actionable report.
 *
 * <p>Runs the pipeline in order — map every vulnerability Mend returned, at every severity, to a
 * published finding, sort them deterministically — then attaches the severity summary and the
 * generation timestamp. The report intentionally includes Critical, High, Medium, Low and Other
 * alike; sorting (see {@link ActionableFindingOrder}) is what puts the most severe first.
 *
 * <p>The {@link Clock} is injected rather than read from {@code Instant.now()} so the timestamp is
 * a value a test can control. Since the report filenames are fixed, {@code generatedAt} is the only
 * thing that identifies which run produced a file, which makes it worth testing rather than
 * assuming.
 *
 * <p>The summary is taken from the {@link SeverityCounts} the caller already computed for the
 * console, not recomputed here. That is deliberate: sharing one set of counts is what makes it
 * impossible for the report on disk to disagree with the summary on screen.
 */
public final class ActionableReportFactory {

    private final Clock clock;

    public ActionableReportFactory(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** The production factory, stamping reports in UTC. */
    public static ActionableReportFactory systemUtc() {
        return new ActionableReportFactory(Clock.systemUTC());
    }

    /**
     * Builds the report.
     *
     * @param allVulnerabilities every entry Mend returned, at every severity. May be {@code null}.
     *                           Every entry is included in the report — nothing is filtered out.
     * @param counts             the counts already computed from that same list for the console
     * @throws IllegalStateException if the counts do not correspond to the vulnerabilities, which
     *                               would mean the report contradicted the console summary
     */
    public ActionableReport build(List<VulnerabilityRecord> allVulnerabilities,
                                  SeverityCounts counts) {
        Objects.requireNonNull(counts, "counts");

        List<ActionableFinding> findings =
                ActionableFindingOrder.sorted(ActionableReportMapper.toFindings(allVulnerabilities));

        verifyConsistentWithSummary(counts, findings.size());

        return ActionableReport.of(
                generatedAt(),
                toSummary(counts, findings.size()),
                findings);
    }

    /**
     * Truncated to whole seconds. Sub-second precision carries no meaning for a manually run scan,
     * and dropping it keeps {@code generatedAt} a predictable, comparable length.
     */
    private String generatedAt() {
        return DateTimeFormatter.ISO_INSTANT.format(clock.instant().truncatedTo(ChronoUnit.SECONDS));
    }

    /**
     * @param findingCount the number of findings actually produced; kept as a separate field
     *                      ({@code actionableCount} in the JSON) rather than removed, even though
     *                      it now always equals {@code total}, so the published schema does not
     *                      change shape for existing consumers.
     */
    private static ActionableSummary toSummary(SeverityCounts counts, int findingCount) {
        return new ActionableSummary(
                counts.total(),
                counts.criticalCount(),
                counts.highCount(),
                counts.mediumCount(),
                counts.lowCount(),
                counts.otherCount(),
                findingCount);
    }

    /**
     * Guards the one invariant that ties the two outputs together.
     *
     * <p>Every vulnerability is mapped into a finding, so the finding count must equal
     * {@code counts.total()}. A mismatch means the caller supplied counts computed from a
     * different list — and the resulting report would claim one total while listing a different
     * number of findings. Downstream automation would act on that, so it fails here instead.
     */
    private static void verifyConsistentWithSummary(SeverityCounts counts, int findingCount) {
        int expected = counts.total();
        if (expected != findingCount) {
            throw new IllegalStateException(
                    "Report would contradict the summary: the summary reports " + expected
                            + " total vulnerabilities but " + findingCount
                            + " findings were produced. The counts do not belong to this scan.");
        }
    }
}
