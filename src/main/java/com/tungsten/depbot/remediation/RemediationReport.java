package com.tungsten.depbot.remediation;

import com.tungsten.depbot.assessment.AutomationSafety;
import com.tungsten.depbot.assessment.PlannedDependencyChange;
import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;
import com.tungsten.depbot.validation.ValidationStatus;

import java.util.List;
import java.util.Map;

/**
 * The mandatory, strict report attached to one remediation group's successful commit -- a reviewer
 * opening that commit must be able to answer what/why/why-this-way/where/who/how-checked from this
 * document alone, without having to reconstruct it from the free-form {@code ImplementationReport}.
 *
 * <p>Deliberately not the same document as {@code ImplementationReport}: that one is Claude's own
 * free-form account of what it did, kept verbatim because it is the record of the call itself. This one
 * is assembled by the bot afterward, from that account plus what the analysis and the bot's own
 * validation/build gates actually established -- so {@code whatChanged}/{@code whyNecessary}/
 * {@code whyThisRemediation}/{@code validationPerformed} are never solely Claude's unverified word,
 * and {@code commitSha} is filled in only once the commit genuinely exists (Claude cannot know it in
 * advance).
 *
 * <p>Written as {@code remediation-report.json} alongside the existing {@code implementation-report.json}
 * in the group's own unit directory -- both are kept, neither replaces the other.
 */
public record RemediationReport(
        String schemaVersion,
        String commitSha,
        String groupId,
        List<String> memberCoordinates,
        String whatChanged,
        String whyNecessary,
        String whyThisRemediation,
        List<String> whereChanged,
        String validationPerformed,
        List<VersionChange> versionChanges,
        ValidationStatus dependencyValidationStatus,
        ValidationStatus fullBuildValidationStatus,
        JenkinsValidationOutcome isolatedJenkinsValidation,
        JenkinsValidationOutcome integrationJenkinsValidation,
        String acceptedBaseSha,
        JenkinsValidationOutcome cumulativeJenkinsValidation,
        AutomationSafety automationSafety,
        String automationSafetyReason,
        String effectiveRiskReason,
        String fullBuildValidationCommand,
        List<String> remainingWork,
        List<PlannedDependencyChange> plannedChanges,
        List<String> whatChangedItems,
        List<String> validationPerformedItems,
        Map<String, String> resolvedVersionsByCoordinates) {

    /** The schema generation this application understands. */
    public static final String CURRENT_SCHEMA_VERSION = "1.0";

    public RemediationReport {
        schemaVersion = (schemaVersion == null || schemaVersion.isBlank())
                ? CURRENT_SCHEMA_VERSION
                : schemaVersion.strip();
        memberCoordinates = memberCoordinates == null ? List.of() : List.copyOf(memberCoordinates);
        whereChanged = whereChanged == null ? List.of() : List.copyOf(whereChanged);
        versionChanges = versionChanges == null ? List.of() : List.copyOf(versionChanges);
        remainingWork = remainingWork == null ? List.of() : List.copyOf(remainingWork);
        plannedChanges = plannedChanges == null ? List.of() : List.copyOf(plannedChanges);
        whatChangedItems = whatChangedItems == null ? List.of() : List.copyOf(whatChangedItems);
        validationPerformedItems = validationPerformedItems == null ? List.of() : List.copyOf(validationPerformedItems);
        resolvedVersionsByCoordinates = resolvedVersionsByCoordinates == null
                ? Map.of() : Map.copyOf(resolvedVersionsByCoordinates);
    }

    /**
     * The confirmed version {@code coordinates} was actually found resolving to after this commit, per the
     * dependency-resolution gate -- {@code null} when that gate never established one for this coordinate
     * (it may still be covered by a {@link #plannedChanges()} entry with no confirmed evidence) or when the
     * stored value is blank; a caller must never treat a blank string as a confirmed version.
     */
    public String resolvedVersionFor(String coordinates) {
        String resolved = resolvedVersionsByCoordinates.get(coordinates);
        return (resolved == null || resolved.isBlank()) ? null : resolved;
    }

    /**
     * The shape this record had before {@code fullBuildValidationCommand}/{@code remainingWork}/
     * {@code plannedChanges}/{@code whatChangedItems}/{@code validationPerformedItems} existed -- every new
     * field defaults to {@code null}/empty. A purely additive JSON-schema change: the legacy
     * {@code whatChanged}/{@code validationPerformed} string fields keep their exact original type and
     * content, so any consumer reading only those two fields is unaffected. Kept so every existing
     * caller/test keeps compiling and behaving unchanged.
     */
    public RemediationReport(
            String schemaVersion,
            String commitSha,
            String groupId,
            List<String> memberCoordinates,
            String whatChanged,
            String whyNecessary,
            String whyThisRemediation,
            List<String> whereChanged,
            String validationPerformed,
            List<VersionChange> versionChanges,
            ValidationStatus dependencyValidationStatus,
            ValidationStatus fullBuildValidationStatus,
            JenkinsValidationOutcome isolatedJenkinsValidation,
            JenkinsValidationOutcome integrationJenkinsValidation,
            String acceptedBaseSha,
            JenkinsValidationOutcome cumulativeJenkinsValidation,
            AutomationSafety automationSafety,
            String automationSafetyReason,
            String effectiveRiskReason) {
        this(schemaVersion, commitSha, groupId, memberCoordinates, whatChanged, whyNecessary,
                whyThisRemediation, whereChanged, validationPerformed, versionChanges,
                dependencyValidationStatus, fullBuildValidationStatus, isolatedJenkinsValidation,
                integrationJenkinsValidation, acceptedBaseSha, cumulativeJenkinsValidation,
                automationSafety, automationSafetyReason, effectiveRiskReason,
                null, null, null, null, null, null);
    }

    /**
     * The shape this record had before the progressive-cumulative migration -- {@code acceptedBaseSha}
     * and {@code cumulativeJenkinsValidation} default to {@code null}. Kept so every existing caller
     * (chiefly tests building a fixture report with the isolated-model's own field,
     * {@code isolatedJenkinsValidation}) keeps compiling and behaving unchanged; new production code
     * always uses the full canonical constructor and never populates {@code isolatedJenkinsValidation}.
     */
    public RemediationReport(
            String schemaVersion,
            String commitSha,
            String groupId,
            List<String> memberCoordinates,
            String whatChanged,
            String whyNecessary,
            String whyThisRemediation,
            List<String> whereChanged,
            String validationPerformed,
            List<VersionChange> versionChanges,
            ValidationStatus dependencyValidationStatus,
            ValidationStatus fullBuildValidationStatus,
            JenkinsValidationOutcome isolatedJenkinsValidation,
            JenkinsValidationOutcome integrationJenkinsValidation) {
        this(schemaVersion, commitSha, groupId, memberCoordinates, whatChanged, whyNecessary,
                whyThisRemediation, whereChanged, validationPerformed, versionChanges,
                dependencyValidationStatus, fullBuildValidationStatus, isolatedJenkinsValidation,
                integrationJenkinsValidation, null, null, null, null);
    }

    /**
     * The shape this record had before risky-group remediation was added -- {@code automationSafety} and
     * {@code automationSafetyReason} default to {@code null}, which reads as "ordinary/automatic" (every
     * pre-existing report is exactly that, since only {@code AUTOMATIC_ALLOWED} groups ever produced one
     * before this addition). Kept so every existing caller/test keeps compiling and behaving unchanged.
     */
    public RemediationReport(
            String schemaVersion,
            String commitSha,
            String groupId,
            List<String> memberCoordinates,
            String whatChanged,
            String whyNecessary,
            String whyThisRemediation,
            List<String> whereChanged,
            String validationPerformed,
            List<VersionChange> versionChanges,
            ValidationStatus dependencyValidationStatus,
            ValidationStatus fullBuildValidationStatus,
            JenkinsValidationOutcome isolatedJenkinsValidation,
            JenkinsValidationOutcome integrationJenkinsValidation,
            String acceptedBaseSha,
            JenkinsValidationOutcome cumulativeJenkinsValidation) {
        this(schemaVersion, commitSha, groupId, memberCoordinates, whatChanged, whyNecessary,
                whyThisRemediation, whereChanged, validationPerformed, versionChanges,
                dependencyValidationStatus, fullBuildValidationStatus, isolatedJenkinsValidation,
                integrationJenkinsValidation, acceptedBaseSha, cumulativeJenkinsValidation, null, null, null);
    }

    /**
     * The shape this record had before {@code effectiveRiskReason} existed -- defaults it to {@code null}.
     * Kept so every existing caller keeps compiling unchanged.
     */
    public RemediationReport(
            String schemaVersion,
            String commitSha,
            String groupId,
            List<String> memberCoordinates,
            String whatChanged,
            String whyNecessary,
            String whyThisRemediation,
            List<String> whereChanged,
            String validationPerformed,
            List<VersionChange> versionChanges,
            ValidationStatus dependencyValidationStatus,
            ValidationStatus fullBuildValidationStatus,
            JenkinsValidationOutcome isolatedJenkinsValidation,
            JenkinsValidationOutcome integrationJenkinsValidation,
            String acceptedBaseSha,
            JenkinsValidationOutcome cumulativeJenkinsValidation,
            AutomationSafety automationSafety,
            String automationSafetyReason) {
        this(schemaVersion, commitSha, groupId, memberCoordinates, whatChanged, whyNecessary,
                whyThisRemediation, whereChanged, validationPerformed, versionChanges,
                dependencyValidationStatus, fullBuildValidationStatus, isolatedJenkinsValidation,
                integrationJenkinsValidation, acceptedBaseSha, cumulativeJenkinsValidation,
                automationSafety, automationSafetyReason, null);
    }

    /**
     * The group's own Jenkins outcome, whichever field a run of this application actually populated:
     * {@code cumulativeJenkinsValidation} for a run made under the progressive-cumulative model,
     * {@code isolatedJenkinsValidation} for one made under the earlier isolated model. Never both at
     * once in practice -- new code writes only the former, old persisted reports carry only the latter.
     * Every caller that needs "did this group's own Jenkins gate pass" (publication eligibility, Markdown
     * rendering) uses this method rather than reading either field directly, so both generations of
     * persisted report remain correctly readable.
     */
    public JenkinsValidationOutcome effectiveGroupJenkinsValidation() {
        return cumulativeJenkinsValidation != null ? cumulativeJenkinsValidation : isolatedJenkinsValidation;
    }

    /**
     * Whether the full application build ({@link #fullBuildValidationCommand()}) both ran and passed after
     * this commit -- the one fact a report must never overstate. {@code false} for {@code NOT_RUN} as firmly as for
     * {@code FAILED}: a build that never got a verdict is not evidence the remediation is sound.
     */
    public boolean fullyBuildValidated() {
        return fullBuildValidationStatus == ValidationStatus.PASSED;
    }

    /**
     * Whether this commit is Jenkins-validated end to end: its own isolated candidate passed, AND the
     * cohort's combined branch it was later assembled into also passed its separate final integration
     * gate. A successful {@code isolatedJenkinsValidation} alone is never enough to answer {@code true}
     * -- that would let a report imply full Jenkins validation before the combined branch was even
     * checked, exactly the overstatement the two-gate design exists to prevent.
     */
    public boolean jenkinsValidated() {
        JenkinsValidationOutcome group = effectiveGroupJenkinsValidation();
        return group != null && group.succeeded()
                && integrationJenkinsValidation != null && integrationJenkinsValidation.succeeded();
    }

    /**
     * One member's version transition, as the bot itself established it -- never invented. {@code
     * toVersion} is {@code null} when no actual resolved version, Mend suggestion, or group
     * recommendation was available to fall back to (see {@code RemediationImplementationService}'s own
     * three-tier fallback, which {@code RemediationReportFactory} reuses to build this list).
     */
    public record VersionChange(String coordinates, String fromVersion, String toVersion) {
    }
}
