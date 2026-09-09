package com.tungsten.depbot.publication;

import com.tungsten.depbot.humanreview.HumanReviewReport;
import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;
import com.tungsten.depbot.remediation.CohortIntegrationFailureOutcome;
import com.tungsten.depbot.remediation.RejectedGroupOutcome;
import com.tungsten.depbot.validation.MavenBuildValidationGate;
import com.tungsten.depbot.validation.ValidationStatus;

import java.util.List;
import java.util.Objects;

/**
 * Renders an already-written {@link HumanReviewReport} (plus, when applicable, one of the two bot-owned
 * failure dossiers) as a decision-first GitLab Issue body -- a developer should be able to tell in
 * 20-30 seconds what is vulnerable, what automation did, whether checks passed, and what is needed from
 * them, with long-form investigation evidence pushed into a collapsible section at the very bottom.
 *
 * <p>All three shapes this renderer handles -- a plain review (never attempted), a rejected automatic
 * attempt ({@link RejectedGroupOutcome}), and a cohort whose assembled result failed final integration
 * ({@link CohortIntegrationFailureOutcome}) -- share this exact same section order; only the middle
 * "what happened" content differs, driven by whichever dossier (if any) is supplied.
 *
 * <p>Always ends with an explicit, unmissable statement that no automatic code modification was
 * published as a result of this review -- the one fact every reader must never be left to assume.
 */
public final class HumanReviewReportMarkdownRenderer {

    /** As {@link #render(HumanReviewReport, RejectedGroupOutcome, CohortIntegrationFailureOutcome)}. */
    public String render(HumanReviewReport report) {
        return render(report, null, null);
    }

    /** As {@link #render(HumanReviewReport, RejectedGroupOutcome, CohortIntegrationFailureOutcome)}. */
    public String render(HumanReviewReport report, RejectedGroupOutcome rejectedGroupOutcome) {
        return render(report, rejectedGroupOutcome, null);
    }

    /**
     * @param rejectedGroupOutcome     the bot-owned dossier of exactly why an attempted automatic group
     *                                 was rejected, or {@code null} when this review was never about a
     *                                 rejected automatic attempt at all; mutually exclusive with
     *                                 {@code cohortIntegrationFailure}
     * @param cohortIntegrationFailure the bot-owned dossier for a cohort whose every group was
     *                                 individually accepted but whose final-integration Jenkins gate
     *                                 failed for the assembled set, or {@code null} otherwise
     */
    public String render(HumanReviewReport report, RejectedGroupOutcome rejectedGroupOutcome,
            CohortIntegrationFailureOutcome cohortIntegrationFailure) {
        Objects.requireNonNull(report, "report");

        StringBuilder md = new StringBuilder();
        appendTitleAndGlance(md, report, rejectedGroupOutcome, cohortIntegrationFailure);
        appendRecommendedChange(md, report);
        appendAutomationOutcome(md, rejectedGroupOutcome, cohortIntegrationFailure);
        appendRiskBanner(md, rejectedGroupOutcome, cohortIntegrationFailure);
        appendRecommendedAction(md, rejectedGroupOutcome, cohortIntegrationFailure);
        appendValidationTable(md, report, rejectedGroupOutcome, cohortIntegrationFailure);
        appendJenkinsHeadline(md, report, cohortIntegrationFailure);
        appendWhatTheBotChanged(md, rejectedGroupOutcome, cohortIntegrationFailure);
        appendFailureSummaryAndPlanningHistory(md, rejectedGroupOutcome);
        appendPatch(md, rejectedGroupOutcome, cohortIntegrationFailure);
        appendReproduction(md, rejectedGroupOutcome, cohortIntegrationFailure);
        appendResidualRisks(md, report, rejectedGroupOutcome);
        appendDetails(md, report, rejectedGroupOutcome, cohortIntegrationFailure);

        md.append("**Automatic code modification performed:** NO\n");
        return md.toString();
    }

    // ---- 1-2. title + at-a-glance ------------------------------------------------------------------

    private static void appendTitleAndGlance(StringBuilder md, HumanReviewReport report,
            RejectedGroupOutcome rejected, CohortIntegrationFailureOutcome cohort) {
        String title = cohort != null
                ? "Cohort publication blocked -- " + cohort.acceptedGroupIds().size() + " group(s) on `"
                        + cohort.branchName() + "`"
                : "Human review required -- " + report.coordinates();
        md.append("## ").append(title).append("\n\n");

        md.append("| | |\n|---|---|\n");
        if (cohort != null) {
            md.append("| Branch | `").append(text(cohort.branchName())).append("` |\n");
            md.append("| Verified source ref | ").append(text(cohort.verifiedSourceRef())).append(" |\n");
            md.append("| Verified source SHA (S0) | `").append(text(cohort.verifiedSourceSha())).append("` |\n");
            md.append("| Accepted groups | ").append(cohort.acceptedGroupIds().isEmpty()
                    ? "(none)" : String.join(", ", cohort.acceptedGroupIds())).append(" |\n");
            md.append("| Status | Cohort publication blocked |\n");
        } else {
            md.append("| Coordinates | ").append(text(report.coordinates())).append(" |\n");
            if (rejected != null) {
                md.append("| Group | ").append(text(rejected.groupId())).append(" |\n");
                md.append("| Priority | ").append(text(rejected.priority())).append(" |\n");
                md.append("| Stage where the attempt stopped | ").append(rejected.stoppedAtStage()).append(" |\n");
                md.append("| Status | Automatic attempt rejected |\n");
            } else {
                md.append("| Status | Never attempted automatically |\n");
            }
        }
        md.append('\n');
    }

    // ---- 3. dependency/version info -----------------------------------------------------------------

    private static void appendRecommendedChange(StringBuilder md, HumanReviewReport report) {
        md.append("**What is vulnerable:**\n\n").append(text(report.vulnerabilitySummary())).append("\n\n");
        md.append("**Recommended change:**\n\n").append(text(report.recommendedChange())).append("\n\n");
    }

    // ---- 4. automation outcome ------------------------------------------------------------------------

    private static void appendAutomationOutcome(StringBuilder md, RejectedGroupOutcome rejected,
            CohortIntegrationFailureOutcome cohort) {
        String line;
        if (cohort != null) {
            line = "Every group in this cohort was individually accepted, but the fully assembled branch "
                    + "failed a separate final integration check, so none of them are published.";
        } else if (rejected != null) {
            line = "Automation attempted this remediation and could not complete it.";
        } else {
            line = "Automation did not attempt this finding.";
        }
        md.append("**Automation outcome:** ").append(line).append("\n\n");
    }

    // ---- 5. risk/status banner -------------------------------------------------------------------------

    private static void appendRiskBanner(StringBuilder md, RejectedGroupOutcome rejected,
            CohortIntegrationFailureOutcome cohort) {
        if (cohort != null) {
            md.append("> **Attribution:** ").append(text(cohort.attributionNote())).append("\n\n");
        } else if (rejected != null) {
            md.append("> **Exact failure reason:** ").append(text(rejected.failureReason())).append("\n\n");
        }
    }

    // ---- 6. recommended action ------------------------------------------------------------------------

    private static void appendRecommendedAction(StringBuilder md, RejectedGroupOutcome rejected,
            CohortIntegrationFailureOutcome cohort) {
        String action;
        if (cohort != null) {
            action = "A human must investigate the combination of accepted groups and decide how to proceed; "
                    + "each group's own commit remains locally committed but unpublished.";
        } else if (rejected != null) {
            action = "A human must review the plan/implementation history below and decide the next step.";
        } else {
            action = "A human must establish a remediation plan for this finding.";
        }
        md.append("**Recommended action:** ").append(action).append("\n\n");
    }

    // ---- 7. combined validation-results table ----------------------------------------------------------

    private static void appendValidationTable(StringBuilder md, HumanReviewReport report,
            RejectedGroupOutcome rejected, CohortIntegrationFailureOutcome cohort) {
        md.append("| Check | Result |\n|---|---|\n");
        if (rejected != null) {
            md.append("| Dependency validation | ").append(statusMark(rejected.dependencyValidationStatus()))
                    .append(" |\n");
            md.append("| Full build | ").append(statusMark(rejected.fullBuildValidationStatus())).append(" |\n");
        } else {
            md.append("| Dependency validation | ⚠ NOT APPLICABLE |\n");
            md.append("| Full build | ⚠ NOT APPLICABLE |\n");
        }
        JenkinsValidationOutcome cumulative = cohort != null ? null : report.effectiveGroupJenkinsValidation();
        JenkinsValidationOutcome integration = cohort != null
                ? cohort.integrationJenkinsValidation() : report.integrationJenkinsValidation();
        md.append("| Cumulative Jenkins | ").append(jenkinsMark(cumulative)).append(" |\n");
        md.append("| Final integration Jenkins | ").append(jenkinsMark(integration)).append(" |\n");
        md.append('\n');
    }

    private static String statusMark(ValidationStatus status) {
        if (status == null) {
            return "⚠ NOT APPLICABLE";
        }
        return switch (status) {
            case PASSED -> "✓ PASSED";
            case FAILED -> "✗ FAILED";
            case NOT_RUN -> "⚠ NOT RUN";
        };
    }

    private static String jenkinsMark(JenkinsValidationOutcome outcome) {
        if (outcome == null) {
            return "⚠ NOT APPLICABLE";
        }
        return (outcome.succeeded() ? "✓ " : "✗ ") + outcome.status();
    }

    // ---- 8. Jenkins headline -----------------------------------------------------------------------------

    private static void appendJenkinsHeadline(StringBuilder md, HumanReviewReport report,
            CohortIntegrationFailureOutcome cohort) {
        JenkinsValidationOutcome headline = cohort != null
                ? cohort.integrationJenkinsValidation()
                : (report.effectiveGroupJenkinsValidation() != null
                        ? report.effectiveGroupJenkinsValidation() : report.integrationJenkinsValidation());
        if (headline != null && headline.buildUrl() != null && !headline.buildUrl().isBlank()) {
            md.append("**Jenkins:** ").append(jenkinsMark(headline)).append(" -- ")
                    .append(headline.buildUrl()).append("\n\n");
        }
    }

    // ---- 9. what the bot changed --------------------------------------------------------------------------

    private static void appendWhatTheBotChanged(StringBuilder md, RejectedGroupOutcome rejected,
            CohortIntegrationFailureOutcome cohort) {
        md.append("**What the bot did:**\n\n");
        if (cohort != null) {
            if (cohort.perGroupValidationSummaries().isEmpty()) {
                md.append("- (none noted)\n");
            } else {
                for (String line : cohort.perGroupValidationSummaries()) {
                    md.append("- ").append(line).append('\n');
                }
            }
        } else if (rejected != null) {
            md.append("- ").append(text(rejected.whatWasAttempted())).append('\n');
            if (!rejected.whatChanged().isEmpty()) {
                for (String line : rejected.whatChanged()) {
                    md.append("  - ").append(line).append('\n');
                }
            }
        } else {
            md.append("- Nothing; this finding was never attempted automatically.\n");
        }
        md.append('\n');
    }

    // ---- 10. failure summary + risk/conformance evidence -----------------------------------------------

    private static void appendFailureSummaryAndPlanningHistory(StringBuilder md, RejectedGroupOutcome rejected) {
        if (rejected == null) {
            return;
        }
        md.append("### Attempt history\n\n");
        md.append("- Stage where the attempt stopped: ").append(rejected.stoppedAtStage()).append('\n');
        md.append("- Implementation conclusion: ").append(text(rejected.implementationConclusion() == null
                ? null : rejected.implementationConclusion().toString())).append('\n');
        md.append("- Rollback succeeded: ").append(rejected.rollbackSucceeded()).append('\n');
        md.append("- Pipeline continued to the next group: ").append(rejected.pipelineContinued()).append("\n\n");

        if (rejected.effectiveRiskReason() != null) {
            md.append("**Why this group was risky:** ").append(text(rejected.effectiveRiskReason())).append("\n\n");
        }
        if (!rejected.conformanceViolations().isEmpty()) {
            md.append("**Plan-conformance violations a Java-owned structural check found:**\n\n");
            for (String violation : rejected.conformanceViolations()) {
                md.append("- ").append(violation).append('\n');
            }
            md.append('\n');
        }
    }

    // ---- 11. copyable patch/diff -------------------------------------------------------------------------

    private static void appendPatch(StringBuilder md, RejectedGroupOutcome rejected,
            CohortIntegrationFailureOutcome cohort) {
        String patch = cohort != null ? cohort.cumulativePatch() : (rejected != null ? rejected.applicablePatch() : null);
        if (patch == null || patch.isBlank()) {
            if (rejected != null || cohort != null) {
                md.append("**Patch:** no code change was produced for this attempt.\n\n");
            }
            return;
        }
        md.append("**Patch (redacted, applicable via `git apply`):**\n\n```diff\n").append(patch);
        if (!patch.endsWith("\n")) {
            md.append('\n');
        }
        md.append("```\n\n");
    }

    // ---- 12. reproduction ---------------------------------------------------------------------------------

    private static void appendReproduction(StringBuilder md, RejectedGroupOutcome rejected,
            CohortIntegrationFailureOutcome cohort) {
        md.append("**Reproduction:**\n\n");
        if (cohort != null) {
            md.append(text(cohort.reproductionInstructions())).append("\n\n");
            return;
        }
        if (rejected == null) {
            md.append("Not applicable; this finding was never attempted automatically.\n\n");
            return;
        }
        String patch = rejected.applicablePatch();
        if (patch == null || patch.isBlank()) {
            md.append("No code change was produced by automation for this attempt; see the plan/reviewer "
                    + "feedback above for what still needs to be designed.\n\n");
            return;
        }
        String baseSha = text(rejected.acceptedBaseSha());
        md.append("```\n")
                .append("git fetch origin\n")
                .append("git checkout ").append(baseSha).append('\n')
                .append("git apply fix.patch   # save the patch above as fix.patch first\n")
                .append("mvn -o -B dependency:tree -Dincludes=").append(String.join(",", rejected.memberCoordinates()))
                .append('\n')
                .append("mvn ").append(String.join(" ", MavenBuildValidationGate.BUILD_ARGS)).append('\n')
                .append("```\n\n");
    }

    // ---- 13. residual risks --------------------------------------------------------------------------------

    private static void appendResidualRisks(StringBuilder md, HumanReviewReport report, RejectedGroupOutcome rejected) {
        list(md, "Related dependencies to consider", report.relatedDependenciesToConsider());
        list(md, "Open questions", report.openQuestions());
        List<String> risks = report.risks();
        list(md, "Risks", risks);
        if (rejected != null && !rejected.remainingWork().isEmpty()) {
            list(md, "Remaining work", rejected.remainingWork());
        }
        if (rejected != null && !rejected.risks().isEmpty()) {
            list(md, "Risks already identified by automation", rejected.risks());
        }
    }

    // ---- 14. collapsible full investigation evidence ---------------------------------------------------------

    private static void appendDetails(StringBuilder md, HumanReviewReport report, RejectedGroupOutcome rejected,
            CohortIntegrationFailureOutcome cohort) {
        md.append("<details><summary>Full investigation evidence</summary>\n\n");
        md.append("**Why it is vulnerable:**\n\n").append(text(report.whyVulnerable())).append("\n\n");
        md.append("**Where the dependency came from:**\n\n").append(text(report.dependencyOrigin())).append("\n\n");
        md.append("**How to validate a fix:**\n\n").append(text(report.validationApproach())).append("\n\n");

        md.append("### Cumulative Jenkins validation\n\n");
        md.append(jenkinsFacts(cohort != null ? null : report.effectiveGroupJenkinsValidation())).append("\n\n");
        md.append("### Final integration Jenkins validation\n\n");
        JenkinsValidationOutcome integration = cohort != null
                ? cohort.integrationJenkinsValidation() : report.integrationJenkinsValidation();
        md.append(jenkinsFacts(integration)).append("\n\n");

        String consoleLog = cohort != null
                ? cohort.jenkinsConsoleLogExcerpt()
                : (rejected != null && rejected.cumulativeJenkinsValidation() != null
                        ? rejected.cumulativeJenkinsValidation().consoleLogExcerpt() : null);
        if (consoleLog != null && !consoleLog.isBlank()) {
            md.append("**Jenkins console log excerpt (redacted):**\n\n```\n").append(consoleLog);
            if (!consoleLog.endsWith("\n")) {
                md.append('\n');
            }
            md.append("```\n\n");
        }

        if (cohort != null) {
            md.append("**Accepted commits:**\n\n");
            if (cohort.acceptedCommits().isEmpty()) {
                md.append("- (none)\n");
            } else {
                for (var commit : cohort.acceptedCommits()) {
                    md.append("- ").append(commit.groupId()).append(": `").append(commit.commitSha()).append("`\n");
                }
            }
            md.append('\n');
        }

        md.append("</details>\n\n");
    }

    private static String jenkinsFacts(JenkinsValidationOutcome outcome) {
        if (outcome == null) {
            return "- ⚠ NOT APPLICABLE";
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
        section.append("- Result: ").append(text(outcome.resultSummary()));
        return section.toString();
    }

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

    private static String text(String value) {
        return (value == null || value.isBlank()) ? "(not established)" : value;
    }
}
