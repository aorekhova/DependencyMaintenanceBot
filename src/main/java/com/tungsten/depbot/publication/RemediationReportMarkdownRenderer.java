package com.tungsten.depbot.publication;

import com.tungsten.depbot.assessment.PlannedChangeType;
import com.tungsten.depbot.assessment.PlannedDependencyChange;
import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;
import com.tungsten.depbot.remediation.RemediationReport;
import com.tungsten.depbot.validation.ValidationStatus;

import java.util.List;
import java.util.Objects;

/**
 * Deterministically renders an already-written {@link RemediationReport} as Markdown -- never a second
 * Claude call, never a re-derivation of anything. Every fact this prints already exists in the strict
 * JSON document; this class only formats it for a person reading it in GitLab.
 *
 * <p>A {@link RemediationReport} only ever exists for a group's <strong>successful</strong>, already-made
 * commit (see that record's own javadoc) -- a rejected group never produces one at all, so this renderer
 * has no "failure path": there is no patch/diff, no reproduction section, no failure-stage summary here.
 * That entire dossier belongs to {@code HumanReviewReportMarkdownRenderer} instead, which already renders
 * {@code RejectedGroupOutcome}/{@code CohortIntegrationFailureOutcome}.
 *
 * <p>Decision-first layout: a compact title/status, an at-a-glance table, the dependency/version change
 * table, a risk banner for a risky-but-successful group, one combined validation-results table, then what
 * changed and residual risk -- everything a reviewer needs in 20-30 seconds. Long-form investigation
 * detail (why necessary, why this remediation, each Jenkins gate's full structural facts and console log)
 * is pushed into a collapsible section at the bottom, never removed, just no longer first.
 *
 * <p>The full-build line remains the most prominent validation fact and is read only from
 * {@link RemediationReport#fullBuildValidationStatus()}/{@link RemediationReport#fullBuildValidationCommand()}
 * -- the orchestrator's own verified, actually-executed build command and verdict, never a hard-coded
 * command literal and never a build status Claude merely described in prose. A report whose full build did
 * not pass says so plainly; it never reads as "fully validated."
 */
public final class RemediationReportMarkdownRenderer {

    public String render(RemediationReport report) {
        Objects.requireNonNull(report, "report");

        boolean risky = report.effectiveRiskReason() != null;
        boolean fullyValidated = report.dependencyValidationStatus() == ValidationStatus.PASSED
                && report.fullyBuildValidated();

        StringBuilder md = new StringBuilder();

        md.append("# Dependency Remediation -- ").append(report.groupId()).append("\n\n");
        md.append("**Status:** ").append(risky ? "⚠️ Risky change, automated successfully" : "✅ Automated")
                .append(fullyValidated ? "" : " (not fully validated locally -- see validation results)")
                .append("\n\n");

        appendAtAGlance(md, report, risky);
        appendVersionTable(md, report);
        appendPlannedChangesTable(md, report);
        appendOtherPlannedChangesSection(md, report);

        md.append("**Automation outcome:** the Remediation Engineer applied this change and committed it")
                .append(fullyValidated ? "; local validation passed.\n\n" : "; see validation results below.\n\n");

        if (risky) {
            md.append("> ⚠️ **This change remains risky, but automation successfully implemented it and "
                    + "all automated validations passed.** ").append(text(report.effectiveRiskReason()))
                    .append(" This still requires human review before merge -- it is never auto-merged.\n\n");
        }

        boolean hasRemainingWork = !report.remainingWork().isEmpty();
        if (hasRemainingWork) {
            appendRequiredHumanChecks(md, report);
        }

        md.append("**Recommended action:** ").append(recommendedAction(risky, hasRemainingWork)).append("\n\n");

        appendValidationTable(md, report);
        appendJenkinsHeadline(md, report);

        list(md, "What changed", report.whatChangedItems());
        md.append("**Where changed:**\n\n");
        for (String file : report.whereChanged()) {
            md.append("- ").append(file).append('\n');
        }
        if (report.whereChanged().isEmpty()) {
            md.append("- (not established)\n");
        }
        md.append('\n');

        md.append("**Residual risks:**\n\n");
        if (risky) {
            md.append("- ").append(text(report.effectiveRiskReason())).append('\n');
        } else {
            md.append("- none beyond the ordinary review of an automatic dependency bump\n");
        }
        md.append('\n');

        md.append("**Commit SHA:** `").append(report.commitSha()).append("`\n");
        if (report.acceptedBaseSha() != null && !report.acceptedBaseSha().isBlank()) {
            md.append("**Accepted base SHA (this group's own starting point):** `")
                    .append(report.acceptedBaseSha()).append("`\n");
        }
        md.append('\n');

        appendFullEvidenceDetails(md, report);

        return md.toString();
    }

    private static void appendAtAGlance(StringBuilder md, RemediationReport report, boolean risky) {
        md.append("## At a glance\n\n");
        md.append("| | |\n|---|---|\n");
        md.append("| Group | `").append(report.groupId()).append("` |\n");
        md.append("| Libraries | ").append(String.join(", ", report.memberCoordinates())).append(" |\n");
        md.append("| Risk | ").append(risky
                        ? "⚠️ Risky (human-review-required) -- attempted and validated anyway"
                        : "Automatic (routine)")
                .append(" |\n");
        md.append("| Commit | `").append(report.commitSha()).append("` |\n");
        md.append('\n');
    }

    private static void appendVersionTable(StringBuilder md, RemediationReport report) {
        md.append("## Vulnerability findings\n\n");
        if (report.versionChanges().isEmpty()) {
            md.append("| Library |\n| --- |\n");
            for (String coordinates : report.memberCoordinates()) {
                md.append("| ").append(coordinates).append(" |\n");
            }
        } else {
            md.append("| Library | Old version | New version |\n| --- | --- | --- |\n");
            for (RemediationReport.VersionChange change : report.versionChanges()) {
                md.append("| ").append(change.coordinates())
                        .append(" | ").append(text(change.fromVersion()))
                        .append(" | ").append(text(change.toVersion()))
                        .append(" |\n");
            }
        }
        md.append('\n');
    }

    /**
     * Every concrete, machine-readable edit the Vulnerability Analysis Engineer's own plan actually names
     * -- deliberately distinct from {@link #appendVersionTable}, which shows only what a Mend finding
     * itself named. A companion/control-point coordinate with no finding of its own (an
     * {@code httpclient5-cache}, a {@code jackson-bom}) never had anywhere to appear before this section --
     * see the production incident this fixes (pilot {@code 20260909-012226-8bfda1}).
     *
     * <p>Named "Planned / controlled" rather than "Actual": a {@code plannedChanges} entry is the analysis
     * engineer's own plan, not independently re-confirmed evidence for every row. Where the
     * dependency-resolution gate did confirm a coordinate's actually-resolved version
     * ({@link RemediationReport#resolvedVersionFor}), that confirmed value is shown in the "To" column
     * instead of the bare plan target -- but never labelled as confirmed when it is not: a missing or
     * blank confirmation safely falls back to the plan's own {@code targetVersion}, plainly, with no
     * invented evidence and no log/diff parsing.
     *
     * <p><strong>{@code OTHER}-typed entries never appear in this table</strong> (production defect, pilot
     * {@code 20260909-061155-6ca4db}: an {@code OTHER} entry for the same coordinate as a real version
     * bump -- e.g. a third-party-notices regeneration alongside an httpcore5 upgrade -- rendered as a
     * second row here, reading as if the dependency changed version twice). {@code OTHER} means "not one
     * of the three machine-verifiable kinds," so it belongs in {@link #appendOtherPlannedChangesSection}
     * instead, never in a table whose every other row genuinely is a version/structural change. This is
     * rendering categorisation only -- {@code PlannedChangeType}/{@code PlanConformanceGate}'s own
     * {@code OTHER} semantics are untouched, and the entry itself is never dropped from the model.
     */
    private static void appendPlannedChangesTable(StringBuilder md, RemediationReport report) {
        List<PlannedDependencyChange> plannedChanges = report.plannedChanges().stream()
                .distinct()
                .filter(change -> change.changeType() != PlannedChangeType.OTHER)
                .toList();
        if (plannedChanges.isEmpty()) {
            return;
        }
        md.append("## Planned / controlled dependency changes\n\n");
        md.append("| Coordinate | From | To | Change type |\n| --- | --- | --- | --- |\n");
        for (PlannedDependencyChange change : plannedChanges) {
            String confirmed = report.resolvedVersionFor(change.dependencyCoordinates());
            String toVersion = confirmed != null ? confirmed : change.targetVersion();
            md.append("| ").append(change.dependencyCoordinates())
                    .append(" | ").append(text(change.currentVersion()))
                    .append(" | ").append(text(toVersion))
                    .append(" | ").append(change.changeType()).append(" |\n");
        }
        md.append('\n');
    }

    /**
     * {@code OTHER}-typed planned changes -- not a version/structural dependency change at all, so never
     * shown as a second row in {@link #appendPlannedChangesTable} for the same coordinate. Rendered from
     * the same structured {@code PlannedDependencyChange} the plan already carries -- {@code affectedFile}
     * and {@code reason} -- never by parsing {@code patch.diff}. Skipped entirely when there is no
     * {@code OTHER} entry, exactly like the table above.
     */
    private static void appendOtherPlannedChangesSection(StringBuilder md, RemediationReport report) {
        List<PlannedDependencyChange> otherChanges = report.plannedChanges().stream()
                .distinct()
                .filter(change -> change.changeType() == PlannedChangeType.OTHER)
                .toList();
        if (otherChanges.isEmpty()) {
            return;
        }
        md.append("## Other planned changes\n\n");
        for (PlannedDependencyChange change : otherChanges) {
            md.append("- `").append(text(change.affectedFile())).append("` -- ")
                    .append(text(change.reason())).append('\n');
        }
        md.append('\n');
    }

    /**
     * Claude #2's own follow-up checks -- never invented, never supplemented here, only carried through
     * verbatim from {@link RemediationReport#remainingWork()}. Only ever called when that list is
     * non-empty; there is no empty-heading fallback for this section.
     */
    private static void appendRequiredHumanChecks(StringBuilder md, RemediationReport report) {
        md.append("## Required human checks before merge\n\n");
        for (String item : report.remainingWork()) {
            md.append("- [ ] ").append(item).append('\n');
        }
        md.append('\n');
    }

    /**
     * Location-independent on purpose -- never "below"/"above", since where a section actually lands in
     * the rendered document is a layout detail, not something this wording may depend on.
     */
    private static String recommendedAction(boolean risky, boolean hasRemainingWork) {
        if (hasRemainingWork) {
            return "Do not merge until all required human checks have been completed and reviewed.";
        }
        return risky
                ? "Review carefully given the residual risk noted above, then merge if satisfied."
                : "Review and merge if satisfied.";
    }

    private static void appendValidationTable(StringBuilder md, RemediationReport report) {
        md.append("## Validation results\n\n");
        md.append("| Check | Result |\n| --- | --- |\n");
        md.append("| Dependency resolution | ").append(statusCell(report.dependencyValidationStatus())).append(" |\n");
        md.append("| Full application build (").append(fullBuildCommandText(report)).append(") | ")
                .append(statusCell(report.fullBuildValidationStatus())).append(" |\n");
        md.append("| Cumulative Jenkins | ").append(jenkinsCell(report.effectiveGroupJenkinsValidation())).append(" |\n");
        md.append("| Final integration Jenkins | ").append(jenkinsCell(report.integrationJenkinsValidation())).append(" |\n");
        md.append('\n');
        // The exact, unmistakable full-build sentence -- named by command, never folded into a generic
        // status line, and never implying validation on anything but a real PASSED verdict.
        md.append(fullBuildLine(report)).append("\n\n");
    }

    /**
     * The real, executed full-build command, backtick-wrapped -- read from
     * {@link RemediationReport#fullBuildValidationCommand()}, never a hard-coded literal (production
     * defect, pilot {@code 20260909-012226-8bfda1}: this report kept claiming plain {@code mvn -B package}
     * after the gate itself had already switched to a clean build). Falls back to a non-committal generic
     * phrase, never a guessed command, when the build never ran.
     */
    private static String fullBuildCommandText(RemediationReport report) {
        String command = report.fullBuildValidationCommand();
        return (command == null || command.isBlank()) ? "the full application build" : "`" + command + "`";
    }

    private static void appendJenkinsHeadline(StringBuilder md, RemediationReport report) {
        JenkinsValidationOutcome group = report.effectiveGroupJenkinsValidation();
        if (group == null) {
            md.append("**Jenkins:** ⚠ NOT RUN\n\n");
            return;
        }
        md.append("**Jenkins:** ").append(group.succeeded() ? "✓" : "✗").append(' ')
                .append(group.status()).append(" -- ").append(text(group.buildUrl())).append("\n\n");
    }

    private static void appendFullEvidenceDetails(StringBuilder md, RemediationReport report) {
        md.append("<details>\n<summary>Full investigation evidence</summary>\n\n");
        section(md, "Why necessary", report.whyNecessary());
        section(md, "Why this remediation", report.whyThisRemediation());
        list(md, "Validation performed", report.validationPerformedItems());

        md.append("### Cumulative Jenkins validation\n\n");
        md.append(jenkinsSection(report.effectiveGroupJenkinsValidation(),
                "this candidate was validated against the cohort's own verified source SHA together with "
                        + "every previously accepted group in this cohort (or, for a run made before this "
                        + "field existed, validated in isolation from the cohort's own verified source SHA "
                        + "alone)")).append("\n\n");

        md.append("### Final integration Jenkins validation\n\n");
        md.append(jenkinsSection(report.integrationJenkinsValidation(),
                "this is the same result for every commit in this cohort -- it validates the fully "
                        + "assembled branch, not this commit alone")).append("\n\n");

        md.append("</details>\n");
    }

    private static void section(StringBuilder md, String heading, String content) {
        md.append("**").append(heading).append(":**\n\n").append(text(content)).append("\n\n");
    }

    /** One bullet per item -- never a single {@code "; "}-joined paragraph. Empty lists still print the
     *  heading with a "(none noted)" placeholder, since this is only ever called with data known to exist
     *  for this report (an itemized Claude account, or the bot's own validation summary), never an
     *  optional section (see {@link #appendRequiredHumanChecks} for the one section that is genuinely
     *  optional and skips its own heading instead). */
    private static void list(StringBuilder md, String heading, List<String> values) {
        md.append("**").append(heading).append(":**\n\n");
        if (values.isEmpty()) {
            md.append("- (none noted)\n");
        } else {
            for (String value : values) {
                md.append("- ").append(value).append('\n');
            }
        }
        md.append('\n');
    }

    private static String statusCell(ValidationStatus status) {
        return switch (status == null ? ValidationStatus.NOT_RUN : status) {
            case PASSED -> "✓ PASSED";
            case FAILED -> "✗ FAILED";
            case NOT_RUN -> "⚠ NOT RUN";
        };
    }

    private static String jenkinsCell(JenkinsValidationOutcome outcome) {
        if (outcome == null) {
            return "⚠ NOT RUN";
        }
        return (outcome.succeeded() ? "✓ " : "✗ ") + outcome.status();
    }

    /**
     * The one line this whole document exists to make impossible to miss: the orchestrator's own,
     * independently run full-build verdict, called out by name and by the real, actually-executed command
     * -- never folded into a generic status line the way the dependency-resolution gate's is, and never a
     * hard-coded command literal. Also used for the FAILED/NOT_RUN "not fully validated" wording pinned by
     * existing tests.
     */
    private static String fullBuildLine(RemediationReport report) {
        String command = fullBuildCommandText(report);
        ValidationStatus status = report.fullBuildValidationStatus();
        return switch (status == null ? ValidationStatus.NOT_RUN : status) {
            case PASSED -> "- ✓ Full application build after this commit (" + command + "): PASSED";
            case FAILED -> "- ✗ Full application build after this commit (" + command
                    + "): FAILED -- this commit is kept for diagnosis, but is **not** fully validated";
            case NOT_RUN -> "- ⚠ Full application build after this commit (" + command
                    + "): NOT RUN -- this commit is **not** fully validated";
        };
    }

    /**
     * A bot-owned, structured rendering of one {@link JenkinsValidationOutcome} -- every fact here comes
     * straight from the object's own fields, never from anything Claude wrote. {@code null} means the
     * gate was never reached at all, not that it failed.
     */
    private static String jenkinsSection(JenkinsValidationOutcome outcome, String note) {
        if (outcome == null) {
            return "- ⚠ NOT RUN";
        }
        String mark = outcome.succeeded() ? "✓" : "✗";
        StringBuilder section = new StringBuilder();
        section.append("- ").append(mark).append(' ').append(outcome.status()).append('\n');
        section.append("- Job: ").append(outcome.jobName()).append('\n');
        section.append("- Build: ").append(text(outcome.buildNumber() == null ? null : outcome.buildNumber().toString()))
                .append('\n');
        section.append("- Build URL: ").append(text(outcome.buildUrl())).append('\n');
        section.append("- Baseline SHA: `").append(outcome.baselineSha()).append("`\n");
        section.append("- Candidate SHA: `").append(outcome.candidateSha()).append("`\n");
        section.append("- Expected tree SHA: `").append(outcome.expectedTreeSha()).append("`\n");
        section.append("- Result: ").append(text(outcome.resultSummary())).append('\n');
        if (outcome.consoleLogExcerpt() != null && !outcome.consoleLogExcerpt().isBlank()) {
            section.append("- Console log excerpt:\n\n```\n").append(outcome.consoleLogExcerpt()).append("\n```\n");
        }
        section.append('\n').append(note);
        return section.toString();
    }

    private static String text(String value) {
        return (value == null || value.isBlank()) ? "(not established)" : value;
    }
}
