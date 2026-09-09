package com.tungsten.depbot.remediation;

import com.tungsten.depbot.report.Severity;
import com.tungsten.depbot.report.actionable.ActionableFinding;
import com.tungsten.depbot.report.actionable.ActionableReport;
import com.tungsten.depbot.report.actionable.AffectedLibrary;
import com.tungsten.depbot.report.actionable.RecommendedFix;
import com.tungsten.depbot.report.actionable.Remediation;

import java.time.Clock;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Groups an already-published actionable report's findings by exact {@code groupId:artifactId}
 * and produces one remediation entry per library.
 *
 * <p>A finding with no library at all, or with a blank groupId or artifactId, cannot be grouped by
 * an artifact identity and contributes nothing to the plan -- there is nothing to remediate
 * without knowing which library is affected.
 *
 * <p>The current version recorded for a library is taken from the first finding encountered for
 * it. A single scan of a single classpath never reports two different versions of the same
 * library, so reconciling a disagreement is not a case worth building for.
 */
public final class RemediationPlanBuilder {

    private final Clock clock;

    public RemediationPlanBuilder(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public RemediationPlan build(ActionableReport sourceReport) {
        Objects.requireNonNull(sourceReport, "sourceReport");

        Map<String, List<ActionableFinding>> byLibrary = new LinkedHashMap<>();
        for (ActionableFinding finding : sourceReport.findings()) {
            String key = libraryKey(finding.library());
            if (key != null) {
                byLibrary.computeIfAbsent(key, k -> new ArrayList<>()).add(finding);
            }
        }

        List<LibraryRemediation> critical = new ArrayList<>();
        List<LibraryRemediation> high = new ArrayList<>();
        List<LibraryRemediation> medium = new ArrayList<>();
        List<LibraryRemediation> low = new ArrayList<>();
        List<LibraryRemediation> manualAnalysisRequired = new ArrayList<>();

        for (List<ActionableFinding> findings : byLibrary.values()) {
            AffectedLibrary first = findings.get(0).library();

            List<String> vulnerabilityIds = new ArrayList<>();
            List<Set<String>> stableCandidatesPerFinding = new ArrayList<>();
            Severity mostSevere = Severity.OTHER;

            for (ActionableFinding finding : findings) {
                if (finding.vulnerabilityId() != null) {
                    vulnerabilityIds.add(finding.vulnerabilityId());
                }
                Severity severity = Severity.fromRaw(finding.severity());
                if (severity.ordinal() < mostSevere.ordinal()) {
                    mostSevere = severity;
                }
                stableCandidatesPerFinding.add(TargetVersionResolver.stableCandidatesForFinding(
                        first.groupId(), first.artifactId(), fixResolutionsOf(finding.remediation())));
            }

            String targetVersion = TargetVersionResolver.resolve(stableCandidatesPerFinding, first.version());
            String manualAnalysisReason = blockedByDowngradeReason(stableCandidatesPerFinding, targetVersion, first.version());
            LibraryRemediation entry = new LibraryRemediation(
                    first.groupId(),
                    first.artifactId(),
                    first.version(),
                    targetVersion,
                    mostSevere.name(),
                    List.copyOf(vulnerabilityIds),
                    manualAnalysisReason);

            // A version that would close every CVE exists, but only as a downgrade: this needs a
            // human regardless of severity, so it goes to manualAnalysisRequired rather than
            // sitting in its severity bucket with a sentinel target version an execution stage
            // could otherwise mistake for a real one. Every other MANUAL_ANALYSIS_REQUIRED cause
            // (no consistent fix at all, conflicting per-CVE recommendations) keeps its existing,
            // already-tested behaviour of staying in its severity bucket.
            if (manualAnalysisReason != null) {
                manualAnalysisRequired.add(entry);
            } else {
                switch (mostSevere) {
                    case CRITICAL -> critical.add(entry);
                    case HIGH -> high.add(entry);
                    case MEDIUM -> medium.add(entry);
                    case LOW -> low.add(entry);
                    case OTHER -> manualAnalysisRequired.add(entry);
                }
            }
        }

        Comparator<LibraryRemediation> byCoordinates = Comparator.comparing(LibraryRemediation::coordinates);
        critical.sort(byCoordinates);
        high.sort(byCoordinates);
        medium.sort(byCoordinates);
        low.sort(byCoordinates);
        manualAnalysisRequired.sort(byCoordinates);

        return new RemediationPlan(
                generatedAt(),
                sourceReport.generatedAt(),
                RemediationPlan.CURRENT_VERSION,
                critical,
                high,
                medium,
                low,
                manualAnalysisRequired,
                sourceReport.sourceSnapshotFingerprint());
    }

    /**
     * A human-readable reason, or {@code null}. Only ever non-null for the one cause this method
     * can point at plainly: {@link TargetVersionResolver#resolve} fell back to
     * {@code MANUAL_ANALYSIS_REQUIRED}, and a version that would have closed every CVE did exist
     * ({@link TargetVersionResolver#intersectionOf} is non-empty) -- it just was not above the
     * current version. The other {@code MANUAL_ANALYSIS_REQUIRED} causes (no consistent fix found
     * at all) are deliberately left unexplained here, unchanged from before this check existed.
     */
    private static String blockedByDowngradeReason(
            List<Set<String>> stableCandidatesPerFinding, String targetVersion, String currentVersion) {
        if (!TargetVersionResolver.MANUAL_ANALYSIS_REQUIRED.equals(targetVersion)) {
            return null;
        }
        Set<String> intersection = TargetVersionResolver.intersectionOf(stableCandidatesPerFinding);
        if (intersection.isEmpty()) {
            return null;
        }
        return "Mend's fix candidates that close every CVE (" + String.join(", ", intersection)
                + ") are all at or below the current version " + currentVersion
                + " -- no forward fix is available, so this cannot be upgraded automatically.";
    }

    private static String libraryKey(AffectedLibrary library) {
        if (library == null || isBlank(library.groupId()) || isBlank(library.artifactId())) {
            return null;
        }
        return library.groupId() + ":" + library.artifactId();
    }

    private static List<String> fixResolutionsOf(Remediation remediation) {
        List<String> resolutions = new ArrayList<>();
        if (remediation == null) {
            return resolutions;
        }
        RecommendedFix topFix = remediation.topFix();
        if (topFix != null && topFix.fixResolution() != null) {
            resolutions.add(topFix.fixResolution());
        }
        for (RecommendedFix fix : remediation.allFixes()) {
            if (fix != null && fix.fixResolution() != null) {
                resolutions.add(fix.fixResolution());
            }
        }
        return resolutions;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private String generatedAt() {
        return DateTimeFormatter.ISO_INSTANT.format(clock.instant().truncatedTo(ChronoUnit.SECONDS));
    }
}
