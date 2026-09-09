package com.tungsten.depbot.report.actionable;

import java.util.List;

/**
 * One CRITICAL or HIGH vulnerability, described in enough detail to act on.
 *
 * <p>Two representations of the CVSS 3 score are carried on purpose. {@code cvss3Score} is exactly
 * what Mend supplied, so nothing is fabricated; {@code cvss3ScoreNumeric} is the parsed value for
 * machines to compare and sort, and is {@code null} whenever the raw value was absent, blank,
 * unparseable, or not a finite number. Keeping both means the report is faithful and usable at once.
 *
 * <p>{@code library} may be {@code null} when Mend supplied none. {@code locations} and
 * {@code remediation} are never {@code null} — an absent list is empty and an absent remediation is
 * {@link Remediation#empty()} — so consumers can traverse a finding without null checks.
 */
public record ActionableFinding(
        String vulnerabilityId,
        String type,
        String severity,
        String cvss3Severity,
        String cvss3Score,
        Double cvss3ScoreNumeric,
        String score,
        String scoreMetadataVector,
        String description,
        String publishedDate,
        String lastUpdatedDate,
        String referenceUrl,
        String product,
        String project,
        AffectedLibrary library,
        List<FindingLocation> locations,
        Remediation remediation) {

    public ActionableFinding {
        locations = locations == null ? List.of() : List.copyOf(locations);
        remediation = remediation == null ? Remediation.empty() : remediation;
    }
}
