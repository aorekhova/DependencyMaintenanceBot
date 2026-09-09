package com.tungsten.depbot.remediation;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The whole run on one page: {@code reports/runs/<runId>/remediation-summary.json}.
 *
 * <p>Written last, once every library has been attempted, and the one file worth opening first after a
 * run. Everything in it points at detail that already exists in the per-unit directories; nothing is
 * recorded only here, so losing it costs an index rather than evidence.
 */
public record RemediationSummary(
        String runId,
        String generatedAt,
        String summaryVersion,
        String model,
        String repoPath,
        String dependencyFilter,
        List<RemediationSummaryEntry> libraries) {

    public static final String CURRENT_VERSION = "1.0";

    public RemediationSummary {
        summaryVersion = (summaryVersion == null || summaryVersion.isBlank())
                ? CURRENT_VERSION
                : summaryVersion;
        libraries = libraries == null ? List.of() : List.copyOf(libraries);
    }

    public long committedCount() {
        return libraries.stream().filter(RemediationSummaryEntry::committed).count();
    }

    public long nothingToDoCount() {
        return libraries.stream().filter(RemediationSummaryEntry::nothingToDo).count();
    }

    /** Committed and confirmed by the mandatory full build -- the only fully finished state. */
    public long fullyValidatedCount() {
        return libraries.stream().filter(RemediationSummaryEntry::fullyValidated).count();
    }

    /** Committed, but the full build did not pass; the commit stands, kept for diagnosis. */
    public long buildValidationFailedCount() {
        return libraries.stream().filter(RemediationSummaryEntry::buildValidationFailed).count();
    }

    /** Committed and fully validated, but flagged for a person to review before publication or merge. */
    public long humanReviewRequiredCount() {
        return libraries.stream().filter(RemediationSummaryEntry::humanReviewRequired).count();
    }

    public long needsAHumanCount() {
        return libraries.stream().filter(RemediationSummaryEntry::needsAHuman).count();
    }

    /**
     * How many <em>libraries</em> (not groups, not commits) ended up committed -- the same population as
     * {@link #committedCount()}, under a name that cannot be misread as a group or commit count. A group
     * of several libraries remediated together in one commit counts once per library here, exactly as
     * {@link #committedCount()} always has.
     */
    public long librariesRemediatedCount() {
        return committedCount();
    }

    /**
     * How many distinct Claude-defined remediation groups ended up committed -- never the same number as
     * {@link #librariesRemediatedCount()} for a run with any multi-library group, since several libraries
     * of one group share exactly one {@code groupId} and one commit. Grouped by {@code groupId} when one
     * is known; a committed entry with no {@code groupId} recorded (an older artifact, or a singleton
     * group that predates this field) still counts once, keyed by its own {@code commitSha} instead.
     */
    public long automaticGroupCount() {
        return distinctGroupKeys(RemediationSummaryEntry::committed).size();
    }

    /**
     * How many commits landed on a cohort's shared branch -- identical in value to
     * {@link #automaticGroupCount()}, since this codebase's invariant is exactly one commit per group
     * (see {@code VulnerabilityRemediationService}'s own javadoc), but reported under its own name
     * because a reader asking "how many commits" and a reader asking "how many groups" are asking two
     * conceptually different questions that happen, by design, to share one answer.
     */
    public long commitCount() {
        return automaticGroupCount();
    }

    /** How many distinct groups had their own isolated candidate pass isolated Jenkins validation. */
    public long isolatedJenkinsValidatedGroupCount() {
        return distinctGroupKeys(RemediationSummaryEntry::isolatedJenkinsValidated).size();
    }

    /**
     * Every distinct cohort that reached the final integration Jenkins gate, keyed by {@code branchName}
     * -- the cohort's own real, structural identity (the same string {@code CohortsIndex.Entry.branchName()}
     * and {@code RemediationCohort.branchName()} carry), never by comparing {@code
     * JenkinsValidationOutcome} <em>values</em> for equality. Every remediation group in the same cohort
     * shares both the same {@code branchName} and the same {@code integrationJenkinsValidation} value, so
     * value-equality would happen to give the same count here today -- but it is the wrong identity to
     * key on: it conflates "these two records describe the same cohort" with "these two records are
     * field-for-field equal," and a future change to {@code JenkinsValidationOutcome} (or a hypothetical,
     * genuinely distinct cohort whose integration build coincidentally produced identical-looking fields)
     * could silently miscount. {@code branchName} is set on every entry as soon as its group's Phase 1
     * attempt begins (see {@code VulnerabilityRemediationService#implementGroupInIsolation}), always
     * before {@code integrationJenkinsValidation} could ever be populated, so it is never {@code null}
     * for an entry this map actually needs a key for.
     */
    private Map<String, com.tungsten.depbot.jenkins.JenkinsValidationOutcome> integrationOutcomesByCohort() {
        Map<String, com.tungsten.depbot.jenkins.JenkinsValidationOutcome> byBranchName = new java.util.LinkedHashMap<>();
        for (RemediationSummaryEntry entry : libraries) {
            if (entry.integrationJenkinsValidation() == null) {
                continue;
            }
            String cohortKey = entry.branchName() != null ? entry.branchName() : groupKey(entry);
            byBranchName.putIfAbsent(cohortKey, entry.integrationJenkinsValidation());
        }
        return byBranchName;
    }

    /** How many cohorts reached the final integration Jenkins gate at all, whatever the result. */
    public long integrationJenkinsAttemptedCohortCount() {
        return integrationOutcomesByCohort().size();
    }

    /** How many cohorts' final integration Jenkins gate actually succeeded. */
    public long integrationJenkinsSucceededCohortCount() {
        return integrationOutcomesByCohort().values().stream()
                .filter(com.tungsten.depbot.jenkins.JenkinsValidationOutcome::succeeded)
                .count();
    }

    /**
     * How many distinct groups are genuinely {@link RemediationSummaryEntry#readyToPublish() ready to
     * publish} -- committed, with both the isolated and the final integration Jenkins gates succeeded.
     * The commit count for the same population is identical, by the same one-commit-per-group invariant
     * {@link #commitCount()} already relies on.
     */
    public long readyToPublishGroupCount() {
        return distinctGroupKeys(RemediationSummaryEntry::readyToPublish).size();
    }

    /**
     * Every distinct Human Review group in the run, deduplicated by {@code humanReviewDirectory} exactly
     * as {@code GitLabPublicationService.distinctHumanReviewGroups} already does -- every member of a
     * multi-library group shares that one directory. Uses {@code humanReviewReportProduced}, not {@link
     * RemediationSummaryEntry#humanReviewRequired()}, so that a group routed to Human Review only after a
     * failed automatic attempt (never {@code HUMAN_REVIEW_REQUIRED} at the analysis stage) is still
     * counted here.
     */
    public long humanReviewGroupCount() {
        return libraries.stream()
                .filter(entry -> entry.humanReviewDirectory() != null
                        && Boolean.TRUE.equals(entry.humanReviewReportProduced()))
                .map(RemediationSummaryEntry::humanReviewDirectory)
                .distinct()
                .count();
    }

    /** How many libraries, across every Human Review group, actually received a Human Review Report. */
    public long humanReviewLibraryCount() {
        return libraries.stream()
                .filter(entry -> Boolean.TRUE.equals(entry.humanReviewReportProduced()))
                .count();
    }

    /**
     * Everything left over needing direct investigation: a commit whose full build did not pass, plus a
     * library that never reached a committed change, an evidenced "nothing to do", or a prepared Human
     * Review Report -- {@link #buildValidationFailedCount()} and {@link #needsAHumanCount()}, added
     * together as the one number an operator scanning for trouble wants first -- <strong>minus</strong>
     * {@link #automaticRejectedWithReportCount()}: an automatic attempt that was rejected but still
     * produced a Human Review Report is a normal, fully-handled fail-closed outcome, not an unexplained
     * one, and {@code needsAHumanCount()} counts it too (see that method's own javadoc on why it must, and
     * {@link GroupOutcomeState#AUTOMATIC_REJECTED_WITH_REPORT}'s on why it is still distinct from an
     * ordinary "needs a human" case) -- exactly the console's own "handled, not an unexplained failure"
     * wording, which this must not contradict (production defect, pilot {@code 20260908-220923-771c06}:
     * a Jackson group whose automatic attempt was rejected but that produced a working Human Review report
     * -- {@code automaticRejectedNoReportCount() == 0} for it -- was still being counted here as a
     * failure). This never changes which libraries {@link #needsAHumanCount()} itself counts, nor the run's
     * own exit code, which is deliberately still driven by {@code needsAHumanCount()} directly.
     */
    public long failureCount() {
        return buildValidationFailedCount() + needsAHumanCount() - automaticRejectedWithReportCount();
    }

    /** How many groups were accepted into the cumulative chain -- see {@link GroupOutcomeState#ACCEPTED}. */
    public long acceptedGroupCount() {
        return distinctGroupKeys(entry -> entry.groupOutcomeState() == GroupOutcomeState.ACCEPTED).size();
    }

    /**
     * An automatic attempt was made and rejected, but the fallback Human Review report was successfully
     * produced -- a normal, fully-handled fail-closed outcome, not an unexplained failure. See
     * {@link GroupOutcomeState#AUTOMATIC_REJECTED_WITH_REPORT}.
     */
    public long automaticRejectedWithReportCount() {
        return libraries.stream()
                .filter(entry -> entry.groupOutcomeState() == GroupOutcomeState.AUTOMATIC_REJECTED_WITH_REPORT)
                .count();
    }

    /**
     * An automatic attempt was made and rejected, and even the fallback Human Review report could not be
     * produced -- genuinely needs direct investigation. See
     * {@link GroupOutcomeState#AUTOMATIC_REJECTED_NO_REPORT}.
     */
    public long automaticRejectedNoReportCount() {
        return libraries.stream()
                .filter(entry -> entry.groupOutcomeState() == GroupOutcomeState.AUTOMATIC_REJECTED_NO_REPORT)
                .count();
    }

    /**
     * How many findings were left unrouted because their whole-batch Vulnerability Analysis was ruled
     * incomplete -- see {@link GroupOutcomeState#ANALYSIS_INCOMPLETE}. Deliberately not folded into
     * {@link #needsAHumanCount()}/{@link #failureCount()}: ten findings sharing one incomplete batch are
     * one pipeline stoppage, not ten independent failures.
     */
    public long analysisIncompleteFindingCount() {
        return libraries.stream()
                .filter(entry -> entry.groupOutcomeState() == GroupOutcomeState.ANALYSIS_INCOMPLETE)
                .count();
    }

    /**
     * Whether this run's Vulnerability Analysis was ruled incomplete at all -- {@code 1} or {@code 0},
     * never a count of findings (see {@link #analysisIncompleteFindingCount()} for that): the analysis is
     * one whole-batch call, so a run has at most one incomplete-analysis event, however many findings it
     * covered.
     */
    public long analysisIncompleteBatchCount() {
        return analysisIncompleteFindingCount() > 0 ? 1 : 0;
    }

    /**
     * Groups libraries into their Claude-defined remediation group when {@code groupId} is known, or
     * one-per-commit when it is not -- see {@link #automaticGroupCount()} for why a missing {@code
     * groupId} still must not be dropped or double-counted.
     */
    private Set<String> distinctGroupKeys(java.util.function.Predicate<RemediationSummaryEntry> filter) {
        return libraries.stream().filter(filter).map(RemediationSummary::groupKey).collect(Collectors.toSet());
    }

    private static String groupKey(RemediationSummaryEntry entry) {
        return entry.groupId() != null ? "group:" + entry.groupId() : "commit:" + entry.commitSha();
    }
}
