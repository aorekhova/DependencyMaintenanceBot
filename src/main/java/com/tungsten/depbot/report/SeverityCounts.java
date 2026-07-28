package com.tungsten.depbot.report;

import com.tungsten.depbot.mend.model.VulnerabilityRecord;

import java.util.List;
import java.util.Locale;

/**
 * Vulnerability totals grouped by severity.
 *
 * <p>{@code total} always equals the number of entries Mend returned, and always equals the
 * sum of the five buckets. {@code otherCount} is derived by subtraction rather than counted,
 * which makes that invariant structural: no entry can be silently dropped by an unrecognised
 * severity value.
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

        for (VulnerabilityRecord vulnerability : vulnerabilities) {
            switch (normalise(vulnerability)) {
                case "critical" -> critical++;
                case "high" -> high++;
                case "medium" -> medium++;
                case "low" -> low++;
                default -> { /* falls into otherCount via subtraction below */ }
            }
        }

        int total = vulnerabilities.size();
        int other = total - (critical + high + medium + low);
        return new SeverityCounts(total, critical, high, medium, low, other);
    }

    /**
     * Locale.ROOT matters here: under a Turkish default locale {@code "HIGH".toLowerCase()}
     * produces a dotless i, so every HIGH finding would silently land in {@code otherCount}.
     */
    private static String normalise(VulnerabilityRecord vulnerability) {
        if (vulnerability == null || vulnerability.severity() == null) {
            return "";
        }
        return vulnerability.severity().strip().toLowerCase(Locale.ROOT);
    }

    public boolean hasVulnerabilities() {
        return total > 0;
    }
}
