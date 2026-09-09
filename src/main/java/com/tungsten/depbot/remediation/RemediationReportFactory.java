package com.tungsten.depbot.remediation;

import com.tungsten.depbot.assessment.AnalysisRemediationGroup;
import com.tungsten.depbot.assessment.PlannedDependencyChange;
import com.tungsten.depbot.implementation.ImplementationGroupMember;
import com.tungsten.depbot.implementation.ImplementationReport;
import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;
import com.tungsten.depbot.validation.ValidationOutcome;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Builds the strict {@link RemediationReport} for one group's successful commit.
 *
 * <p>Assembled by the bot, not asked of Claude a second time: {@code whatChanged} and
 * {@code whyNecessary} come from what the implementation and the analysis already said,
 * {@code whereChanged} is read from the actual committed diff rather than trusted to Claude's own
 * account, and {@code validationPerformed} folds in the bot's own verified validation/build status
 * alongside Claude's. This is what makes the six-question contract strict where
 * {@code ImplementationReport} is deliberately free-form.
 */
public final class RemediationReportFactory {

    private static final Pattern DIFF_FILE_LINE = Pattern.compile("^diff --git a/(\\S+) b/(\\S+)$");

    private RemediationReportFactory() {
    }

/** As {@link #build(AnalysisRemediationGroup, List, ImplementationReport, String, String, ValidationOutcome,
     * ValidationOutcome, Map, JenkinsValidationOutcome, JenkinsValidationOutcome, String)}, with no
     * {@code acceptedBaseSha} recorded -- kept only for callers that predate the cumulative migration. */
    public static RemediationReport build(
            AnalysisRemediationGroup group,
            List<ImplementationGroupMember> members,
            ImplementationReport implementationReport,
            String commitSha,
            String patch,
            ValidationOutcome validation,
            ValidationOutcome fullBuildValidation,
            Map<String, String> resolvedVersionsByCoordinates,
            JenkinsValidationOutcome isolatedJenkinsValidation,
            JenkinsValidationOutcome integrationJenkinsValidation) {
        return build(group, members, implementationReport, commitSha, patch, validation, fullBuildValidation,
                resolvedVersionsByCoordinates, isolatedJenkinsValidation, integrationJenkinsValidation, null);
    }

    /**
     * @param cumulativeJenkinsValidation this group's own cumulative Jenkins outcome (baseline always the
     *                                    cohort's S0, candidate the cumulative tip through this group) --
     *                                    stored as {@link RemediationReport#cumulativeJenkinsValidation()},
     *                                    never the legacy {@code isolatedJenkinsValidation} field, which
     *                                    new code never populates
     * @param acceptedBaseSha             the cumulative tip this group's own candidate was implemented
     *                                    from ({@code S_{n-1}}) -- distinct from the Jenkins baseline,
     *                                    which is always {@code S0}; {@code null} when not known
     */
    public static RemediationReport build(
            AnalysisRemediationGroup group,
            List<ImplementationGroupMember> members,
            ImplementationReport implementationReport,
            String commitSha,
            String patch,
            ValidationOutcome validation,
            ValidationOutcome fullBuildValidation,
            Map<String, String> resolvedVersionsByCoordinates,
            JenkinsValidationOutcome cumulativeJenkinsValidation,
            JenkinsValidationOutcome integrationJenkinsValidation,
            String acceptedBaseSha) {
        Objects.requireNonNull(group, "group");
        Objects.requireNonNull(members, "members");
        Objects.requireNonNull(implementationReport, "implementationReport");
        Objects.requireNonNull(commitSha, "commitSha");

        List<String> memberCoordinates = members.stream().map(ImplementationGroupMember::coordinates).toList();

        List<String> whatChangedItems = implementationReport.changesMade().isEmpty()
                ? List.of(implementationReport.summary())
                : implementationReport.changesMade();
        String whatChanged = implementationReport.changesMade().isEmpty()
                ? implementationReport.summary()
                : String.join("; ", implementationReport.changesMade());

        String whyNecessary = members.stream()
                .map(member -> member.coordinates() + ": " + member.findingAssessment().summary())
                .collect(Collectors.joining(" | "));

        String whyThisRemediation = isBlank(group.recommendedRemediation())
                ? implementationReport.summary()
                : group.recommendedRemediation();

        List<String> whereChanged = filesChanged(patch);
        if (whereChanged.isEmpty()) {
            whereChanged = group.affectedFiles();
        }

        List<String> validationPerformedItems =
                validationItems(implementationReport, validation, fullBuildValidation);
        String validationPerformed = validationSummary(implementationReport, validation, fullBuildValidation);

        List<RemediationReport.VersionChange> versionChanges = members.stream()
                .map(member -> versionChangeFor(member, group, resolvedVersionsByCoordinates))
                .toList();

        return new RemediationReport(
                RemediationReport.CURRENT_SCHEMA_VERSION,
                commitSha,
                group.groupId(),
                memberCoordinates,
                whatChanged,
                whyNecessary,
                whyThisRemediation,
                whereChanged,
                validationPerformed,
                versionChanges,
                validation == null ? null : validation.status(),
                fullBuildValidation == null ? null : fullBuildValidation.status(),
                null,
                integrationJenkinsValidation,
                acceptedBaseSha,
                cumulativeJenkinsValidation,
                group.automationSafety(),
                group.automationSafetyReason(),
                group.effectiveRiskReason(),
                fullBuildValidation == null ? null : String.join(" ", fullBuildValidation.command()),
                implementationReport.remainingWork(),
                group.plannedChanges(),
                whatChangedItems,
                validationPerformedItems,
                resolvedVersionsByCoordinates);
    }

    /**
     * One member's version transition. {@code toVersion} follows the exact same three-tier trust order
     * as the commit message itself ({@code RemediationImplementationService.targetSuffix}): the actual
     * version the dependency-resolution gate found resolved after the change, then Mend's own
     * per-library suggestion, then the group's shared recommendation -- never invented when none of
     * those is available.
     */
    private static RemediationReport.VersionChange versionChangeFor(
            ImplementationGroupMember member, AnalysisRemediationGroup group,
            Map<String, String> resolvedVersionsByCoordinates) {
        String actual = resolvedVersionsByCoordinates.get(member.coordinates());
        String mendSuggested = member.workItem().botComputedTargetVersion();
        String toVersion;
        if (actual != null && !actual.isBlank()) {
            toVersion = actual;
        } else if (mendSuggested != null && !mendSuggested.isBlank()) {
            toVersion = mendSuggested;
        } else {
            toVersion = group.recommendedTargetVersion();
        }
        return new RemediationReport.VersionChange(
                member.coordinates(), member.workItem().reportedVersion(), toVersion);
    }

    private static List<String> filesChanged(String patch) {
        if (patch == null || patch.isBlank()) {
            return List.of();
        }
        Set<String> files = new LinkedHashSet<>();
        for (String line : patch.split("\n", -1)) {
            Matcher matcher = DIFF_FILE_LINE.matcher(line);
            if (matcher.matches()) {
                files.add(matcher.group(2));
            }
        }
        return List.copyOf(files);
    }

    private static String validationSummary(
            ImplementationReport implementationReport, ValidationOutcome validation, ValidationOutcome fullBuild) {
        StringBuilder summary = new StringBuilder();
        if (!implementationReport.validationPerformed().isEmpty()) {
            summary.append("Claude reported: ")
                    .append(String.join("; ", implementationReport.validationPerformed()));
        }
        if (validation != null) {
            if (!summary.isEmpty()) {
                summary.append(" | ");
            }
            summary.append("Dependency-resolution gate: ").append(validation.status())
                    .append(" (").append(validation.reason()).append(")");
        }
        if (fullBuild != null) {
            if (!summary.isEmpty()) {
                summary.append(" | ");
            }
            summary.append("Full build (").append(String.join(" ", fullBuild.command())).append("): ")
                    .append(fullBuild.status()).append(" (").append(fullBuild.reason()).append(")");
        }
        return summary.isEmpty() ? "No validation was recorded for this commit." : summary.toString();
    }

    /**
     * As {@link #validationSummary}, but one list entry per source instead of a single {@code " | "}-joined
     * paragraph -- built from the exact same inputs, in the same order, so the legacy joined string and
     * this structured list can never disagree with each other.
     *
     * <p>Each of Claude's own {@code implementationReport.validationPerformed()} entries becomes its own
     * list item too -- never re-flattened into one {@code "Claude reported: A; B; C"} item (production
     * defect, pilot {@code 20260909-061155-6ca4db}: the Markdown bullets were already list-shaped, but the
     * structured source handed to the renderer had already re-joined every one of Claude's own items with
     * {@code "; "} before it ever reached this method, so a report with five checks still rendered as one
     * unreadable bullet). No prose is parsed or re-split here -- {@code validationPerformed()} already is
     * a {@code List<String>}; this only stops re-joining it.
     */
    private static List<String> validationItems(
            ImplementationReport implementationReport, ValidationOutcome validation, ValidationOutcome fullBuild) {
        List<String> items = new ArrayList<>();
        for (String checked : implementationReport.validationPerformed()) {
            items.add("Claude: " + checked);
        }
        if (validation != null) {
            items.add("Dependency-resolution gate: " + validation.status()
                    + " (" + validation.reason() + ")");
        }
        if (fullBuild != null) {
            items.add("Full build (" + String.join(" ", fullBuild.command()) + "): " + fullBuild.status()
                    + " (" + fullBuild.reason() + ")");
        }
        return items.isEmpty() ? List.of("No validation was recorded for this commit.") : items;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
