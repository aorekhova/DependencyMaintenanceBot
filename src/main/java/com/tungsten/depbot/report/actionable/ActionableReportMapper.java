package com.tungsten.depbot.report.actionable;

import com.tungsten.depbot.mend.model.MendFix;
import com.tungsten.depbot.mend.model.MendLibrary;
import com.tungsten.depbot.mend.model.MendLocation;
import com.tungsten.depbot.mend.model.VulnerabilityRecord;
import com.tungsten.depbot.report.Severity;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Translates Mend's integration records into published report findings.
 *
 * <p>This is the boundary between what a vendor happens to send and what this application promises
 * its consumers, and it is the single place where "Mend omitted that field" is handled. Two rules
 * are load-bearing:
 *
 * <ul>
 *   <li><strong>Nothing is fabricated.</strong> A missing value stays missing. Library coordinates
 *       in particular are only assembled when groupId, artifactId and version are all genuinely
 *       present — a coordinate built from partial data would look authoritative while being wrong,
 *       and a developer or a future automated remediation step could act on it.</li>
 *   <li><strong>Nothing is lost.</strong> No finding is ever dropped because an optional nested
 *       field was absent, and every non-null fix and location is preserved in its original order.
 *       A {@code null} element in the vulnerabilities list itself is a different case: it is not a
 *       vulnerability at all — Mend's array containing a JSON {@code null} — so {@link #toFindings}
 *       ignores it rather than inventing a finding for it. {@code SeverityCounts} ignores it the
 *       same way when totalling, so the finding count and the total always agree.</li>
 * </ul>
 *
 * <p>Every record is mapped — there is no severity-based filtering here. The report is expected to
 * include every vulnerability Mend returned, at every severity; sorting them by severity (see
 * {@link ActionableFindingOrder}) is what puts the most severe ones first.
 */
public final class ActionableReportMapper {

    private ActionableReportMapper() {
    }

    /**
     * Maps a list of Mend records, one finding per non-{@code null} element, in the input order.
     *
     * <p>A {@code null} element is ignored entirely rather than becoming a finding — see the
     * class-level note on why. This must match {@code SeverityCounts}' treatment of the same
     * list, or the finding count would no longer agree with the summary total.
     *
     * @return an immutable list, one finding per non-{@code null} input record
     */
    public static List<ActionableFinding> toFindings(List<VulnerabilityRecord> vulnerabilities) {
        if (vulnerabilities == null || vulnerabilities.isEmpty()) {
            return List.of();
        }

        List<ActionableFinding> findings = new ArrayList<>();
        for (VulnerabilityRecord vulnerability : vulnerabilities) {
            if (vulnerability != null) {
                findings.add(toFinding(vulnerability));
            }
        }
        return List.copyOf(findings);
    }

    /**
     * Maps one Mend record. Every optional field may be absent; none of them prevents a finding
     * from being produced.
     */
    public static ActionableFinding toFinding(VulnerabilityRecord vulnerability) {
        Objects.requireNonNull(vulnerability, "vulnerability");

        return new ActionableFinding(
                vulnerability.name(),
                vulnerability.type(),
                Severity.fromRaw(vulnerability.severity()).name(),
                vulnerability.cvss3Severity(),
                vulnerability.cvss3Score(),
                parseScore(vulnerability.cvss3Score()),
                vulnerability.score(),
                vulnerability.scoreMetadataVector(),
                vulnerability.description(),
                vulnerability.publishDate(),
                vulnerability.lastUpdatedDate(),
                vulnerability.url(),
                vulnerability.product(),
                vulnerability.project(),
                toLibrary(vulnerability.library()),
                toLocations(vulnerability.locations()),
                toRemediation(vulnerability));
    }

    /**
     * Interprets a raw score as a number, or {@code null} when it cannot be trusted.
     *
     * <p>A {@code try/catch} around {@link Double#parseDouble} is not sufficient on its own:
     * {@code parseDouble} accepts {@code "NaN"}, {@code "Infinity"} and {@code "-Infinity"} without
     * throwing. Those values would then poison any comparison — Java orders {@code NaN} above every
     * real number — so the finite check is a separate, necessary step rather than belt-and-braces.
     */
    static Double parseScore(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            double value = Double.parseDouble(raw.strip());
            return Double.isFinite(value) ? value : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Builds {@code groupId:artifactId:version}, or {@code null} unless all three parts are present
     * and non-blank. Never partially assembled.
     */
    static String coordinatesOf(MendLibrary library) {
        if (library == null
                || isBlank(library.groupId())
                || isBlank(library.artifactId())
                || isBlank(library.version())) {
            return null;
        }
        return library.groupId().strip()
                + ":" + library.artifactId().strip()
                + ":" + library.version().strip();
    }

    private static AffectedLibrary toLibrary(MendLibrary library) {
        if (library == null) {
            return null;
        }
        return new AffectedLibrary(
                library.groupId(),
                library.artifactId(),
                library.version(),
                coordinatesOf(library),
                library.name(),
                library.filename(),
                library.type(),
                library.sha1(),
                library.keyUuid(),
                library.architecture(),
                library.languageVersion(),
                library.description());
    }

    private static List<FindingLocation> toLocations(List<MendLocation> locations) {
        if (locations == null || locations.isEmpty()) {
            return List.of();
        }

        List<FindingLocation> mapped = new ArrayList<>();
        for (MendLocation location : locations) {
            if (location == null) {
                continue;
            }
            // MendLocation declares (matchType, path); FindingLocation declares (path, matchType).
            mapped.add(new FindingLocation(location.path(), location.matchType()));
        }
        return List.copyOf(mapped);
    }

    private static Remediation toRemediation(VulnerabilityRecord vulnerability) {
        RecommendedFix topFix = toFix(vulnerability.topFix());
        List<RecommendedFix> allFixes = toFixes(vulnerability.allFixes());

        if (topFix == null && allFixes.isEmpty()) {
            return Remediation.empty();
        }
        return new Remediation(topFix, allFixes);
    }

    private static List<RecommendedFix> toFixes(List<MendFix> fixes) {
        if (fixes == null || fixes.isEmpty()) {
            return List.of();
        }

        List<RecommendedFix> mapped = new ArrayList<>();
        for (MendFix fix : fixes) {
            if (fix == null) {
                continue;
            }
            mapped.add(toFix(fix));
        }
        return List.copyOf(mapped);
    }

    private static RecommendedFix toFix(MendFix fix) {
        if (fix == null) {
            return null;
        }
        return new RecommendedFix(
                fix.vulnerability(),
                fix.type(),
                fix.origin(),
                fix.url(),
                fix.fixResolution(),
                fix.date(),
                fix.message());
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
