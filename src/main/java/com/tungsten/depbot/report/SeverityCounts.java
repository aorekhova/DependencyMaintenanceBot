package com.tungsten.depbot.report;

import com.tungsten.depbot.mend.model.VulnerabilityRecord;

import java.util.List;

/**
 * Vulnerability totals grouped by severity.
 *
 * <p>{@code total} always equals the number of <em>real</em> Mend entries counted, and always
 * equals the sum of the five buckets. {@code otherCount} is derived by subtraction rather than
 * counted, which makes that invariant structural: no entry can be silently dropped by an
 * unrecognised severity value.
 *
 * <p>A {@code null} element in the vulnerabilities list — Mend's array containing a JSON
 * {@code null} — is not a vulnerability at all, so it is ignored entirely: it does not increment
 * {@code total} and does not fall into {@code otherCount}. This is different from an entry that
 * exists but carries a {@code null} or unrecognised {@code severity}, which is a real Mend record
 * and is still counted, in {@code otherCount}. The detailed report's mapper
 * ({@code com.tungsten.depbot.report.actionable.ActionableReportMapper}) ignores {@code null}
 * elements the same way, so the finding count and this total always agree.
 *
 * <p>Severity normalisation is delegated to {@link Severity} so that the summary and the detailed
 * actionable report can never classify the same finding differently.
 */
public record SeverityCounts(
        int total,
        int criticalCount,
        int highCount,
        int mediumCount,
        int lowCount,
        int otherCount) {

    private static final SeverityCounts EMPTY = new SeverityCounts(0, 0, 0, 0, 0, 0);

    public static SeverityCounts from(List<VulnerabilityRecord> vulnerabilities) {
        if (vulnerabilities == null || vulnerabilities.isEmpty()) {
            return EMPTY;
        }

        int critical = 0;
        int high = 0;
        int medium = 0;
        int low = 0;
        int total = 0;

        for (VulnerabilityRecord vulnerability : vulnerabilities) {
            if (vulnerability == null) {
                // Not a vulnerability at all: ignored, not counted as OTHER.
                continue;
            }
            total++;
            switch (Severity.fromRaw(vulnerability.severity())) {
                case CRITICAL -> critical++;
                case HIGH -> high++;
                case MEDIUM -> medium++;
                case LOW -> low++;
                case OTHER -> { /* falls into otherCount via subtraction below */ }
            }
        }

        int other = total - (critical + high + medium + low);
        return new SeverityCounts(total, critical, high, medium, low, other);
    }

    public boolean hasVulnerabilities() {
        return total > 0;
    }
}
