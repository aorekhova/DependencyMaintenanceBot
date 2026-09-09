package com.tungsten.depbot.humanreview;

import com.tungsten.depbot.assessment.AnalysisRemediationGroup;
import com.tungsten.depbot.assessment.FindingAssessment;
import com.tungsten.depbot.assessment.FindingContextRenderer;
import com.tungsten.depbot.assessment.VulnerabilityWorkItem;
import com.tungsten.depbot.claude.ClaudePhase;
import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;
import com.tungsten.depbot.report.SecretRedactor;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Renders the Human Review Engineer prompt: a technical write-up for a person, never a remediation.
 *
 * <p><strong>This is deliberately not free-form investigation like the Vulnerability Analysis
 * Engineer's.</strong> The analysis (when there is one) already did that work -- this call's job is to
 * turn what it already established into answers for six fixed questions: what is vulnerable, why,
 * where the dependency came from, what needs to change, which related dependencies to consider, and how
 * to validate a fix. Further investigation is legitimate only to close a gap in one specific answer,
 * never to redo the vulnerability analysis, and never to reconsider whether this could be automated --
 * that decision was already made and is not this call's to revisit, however confident it becomes.
 *
 * <p>{@link #render} covers three shapes of input, matching {@link HumanReviewContext}: a full
 * remediation group flagged for review or blocked, a single {@code INCONCLUSIVE} finding, and a finding
 * from a batch whose analysis failed outright, where there is nothing to lean on but the raw Mend
 * finding and whatever context survived the failure.
 */
public final class HumanReviewPromptRenderer {

    /** The document the review must return. Field names match {@link HumanReviewReport}. */
    static final String OUTPUT_SCHEMA = """
            {
              "schemaVersion": "1.0",
              "coordinates": "groupId:artifactId (or a comma-separated list, for a multi-member group)",
              "vulnerabilitySummary": "what is vulnerable",
              "whyVulnerable": "why it is vulnerable",
              "dependencyOrigin": "where the dependency came from",
              "recommendedChange": "what needs to change",
              "relatedDependenciesToConsider": ["related coordinates worth considering, if any"],
              "validationApproach": "how to validate a fix",
              "openQuestions": ["anything the six questions above could not fully answer"],
              "risks": ["risks and caveats a reviewer should know about"]
            }""";

    private final SecretRedactor redactor;
    private final FindingContextRenderer findingRenderer;

    /** A renderer that knows no secrets. Only for callers that genuinely hold none. */
    public HumanReviewPromptRenderer() {
        this(SecretRedactor.none());
    }

    public HumanReviewPromptRenderer(SecretRedactor redactor) {
        this.redactor = Objects.requireNonNull(redactor, "redactor");
        this.findingRenderer = new FindingContextRenderer(redactor);
    }

    public String render(HumanReviewContext context) {
        Objects.requireNonNull(context, "context");

        List<String> lines = new ArrayList<>();
        lines.add(ClaudePhase.HUMAN_REVIEW.promptMarker());
        lines.add("");
        lines.add("# Human review report: " + context.coordinates());
        lines.add("");
        appendRole(lines, context);
        appendFindings(lines, context);
        appendGroupPlan(lines, context.group());
        appendCompanions(lines, context);
        appendFailureContext(lines, context);
        appendJenkinsValidation(lines, context);
        appendRejectedGroupOutcome(lines, context);
        appendCohortIntegrationFailure(lines, context);
        appendAuthority(lines);
        appendExpectedOutput(lines);

        return redactor.redact(String.join("\n", lines) + "\n");
    }

    private static void appendRole(List<String> lines, HumanReviewContext context) {
        lines.add("You are the technical expert preparing a report for a person to act on. **You will not "
                + "implement anything.** Whatever you conclude, however confident you become, this call ends "
                + "with a report, never an edit.");
        lines.add("");
        lines.add("This finding needs a person because: " + context.decisionReason());
        lines.add("");
        if (context.hasFindingAssessments()) {
            lines.add("**A colleague already investigated this and reached the conclusions below.** Your job "
                    + "is to turn what they already established into clear answers to the six fixed "
                    + "questions this report requires -- not to redo their vulnerability, dependency or "
                    + "security analysis from scratch. If their investigation already answers a question, "
                    + "restate it; do not re-verify it independently. Investigate further only to close a "
                    + "specific gap one of the six questions is left with, and stop as soon as you have "
                    + "answered it.");
        } else {
            lines.add("**No usable analysis exists for this finding** -- the earlier attempt at investigating "
                    + "it did not produce one (see below for what, if anything, survived that attempt). You "
                    + "have to establish enough yourself to answer the six fixed questions this report "
                    + "requires, working directly from the Mend finding below. Investigate only as much as "
                    + "answering those six questions genuinely needs -- this is still not the same as the "
                    + "free-form investigation a full vulnerability analysis would do.");
        }
        lines.add("");
        lines.add("**Whatever you find, never decide or comment on whether this could safely be automated.** "
                + "`automationSafety`/`impactScore` are not part of this report and are not yours to revisit "
                + "-- that decision belongs to the analysis phase, not to this one, regardless of what you "
                + "personally conclude while writing this up.");
        lines.add("");
    }

    void appendFindings(List<String> lines, HumanReviewContext context) {
        List<VulnerabilityWorkItem> workItems = context.workItems();
        for (int i = 0; i < workItems.size(); i++) {
            if (workItems.size() > 1) {
                lines.add("## Finding " + (i + 1) + " of " + workItems.size() + ": " + workItems.get(i).coordinates());
                lines.add("");
            }
            findingRenderer.appendTo(lines, workItems.get(i));
            if (i < context.findingAssessments().size()) {
                appendFindingConclusion(lines, context.findingAssessments().get(i));
            }
        }
    }

    void appendFindingConclusion(List<String> lines, FindingAssessment findingAssessment) {
        lines.add("Conclusion from the earlier investigation:");
        lines.add("");
        lines.add("- Conclusion: " + findingAssessment.conclusion());
        lines.add("- Summary: " + text(findingAssessment.summary()));
        lines.add("");
        appendList(lines, "What they established, and how", findingAssessment.evidence());
        appendList(lines, "Risks and unknowns they flagged", findingAssessment.risks());
    }

    void appendGroupPlan(List<String> lines, AnalysisRemediationGroup group) {
        if (group == null) {
            return;
        }
        lines.add("## What the earlier analysis worked out for this group");
        lines.add("");
        lines.add("- Why these findings belong together: " + text(group.groupingReason()));
        lines.add("- Ref assessed: " + text(group.sourceRef()));
        lines.add("- How the dependency was thought to arrive: " + text(group.origin() == null
                ? null : group.origin().name()));
        lines.add("- Relationship: " + text(group.dependencyRelationship()));
        lines.add("- Version observed: " + text(group.observedVersion()));
        lines.add("- Remediation recommended: " + text(group.recommendedRemediation()));
        lines.add("- Target version recommended: " + text(group.recommendedTargetVersion()));
        lines.add("- Why this was flagged for review rather than automated: " + text(group.automationSafetyReason()));
        lines.add("");
        appendList(lines, "Files expected to be involved", group.affectedFiles());
        appendList(lines, "The implementation plan the analysis worked out", group.implementationPlan());
        appendList(lines, "The validation plan the analysis worked out", group.validationPlan());
    }

    static void appendCompanions(List<String> lines, HumanReviewContext context) {
        if (context.companionCoordinates().isEmpty()) {
            return;
        }
        lines.add("## Related coordinates with no Mend finding of their own");
        lines.add("");
        lines.add("The earlier analysis named these as required alongside this group, even though none of "
                + "them has a Mend finding here. Take them into account when answering "
                + "`relatedDependenciesToConsider`.");
        lines.add("");
        for (String companion : context.companionCoordinates()) {
            lines.add("- " + companion);
        }
        lines.add("");
    }

    void appendFailureContext(List<String> lines, HumanReviewContext context) {
        if (!context.hasPriorAnalysisFailure()) {
            return;
        }
        lines.add("## What survived the earlier, failed analysis attempt");
        lines.add("");
        lines.add(text(context.priorAnalysisFailureContext()));
        lines.add("");
    }

    /**
     * A bot-owned, structured account of whichever Jenkins validation attempt is why this review was
     * triggered -- never something for Claude to reconstruct from the prompt's own prose. No-op when
     * neither field is set (Jenkins was never reached for this review at all).
     */
    void appendJenkinsValidation(List<String> lines, HumanReviewContext context) {
        if (!context.hasCumulativeJenkinsValidation() && !context.hasIntegrationJenkinsValidation()) {
            return;
        }
        lines.add("## Jenkins validation");
        lines.add("");
        if (context.hasCumulativeJenkinsValidation()) {
            appendJenkinsFacts(lines, "This group's own cumulative candidate (its own change, on top of "
                            + "every previously accepted group in this cohort) was validated by Jenkins, "
                            + "and rolled back and never published as a result of what follows:",
                    context.cumulativeJenkinsValidation());
        }
        if (context.hasIntegrationJenkinsValidation()) {
            appendJenkinsFacts(lines, "After every group in this cohort was accepted, the fully assembled "
                            + "branch was itself validated by Jenkins as one final integration check -- "
                            + "this group's own change remains on the local branch, but the branch was not "
                            + "marked ready to publish as a result of what follows:",
                    context.integrationJenkinsValidation());
        }
    }

    /**
     * A bot-owned, structured account of exactly why an attempted automatic remediation was rejected --
     * never something for Claude to reconstruct from the prompt's own prose. No-op when this review is
     * not about a rejected automatic attempt at all.
     */
    void appendRejectedGroupOutcome(List<String> lines, HumanReviewContext context) {
        if (!context.hasRejectedGroupOutcome()) {
            return;
        }
        com.tungsten.depbot.remediation.RejectedGroupOutcome outcome = context.rejectedGroupOutcome();
        lines.add("## What the automatic attempt already established");
        lines.add("");
        lines.add("- Priority: " + outcome.priority());
        lines.add("- Execution order: " + (outcome.executionOrder() == null ? FindingContextRenderer.NOT_PROVIDED
                : outcome.executionOrder()));
        lines.add("- Accepted cumulative base SHA this group started from: " + text(outcome.acceptedBaseSha()));
        lines.add("- Stage where the automatic attempt stopped: " + outcome.stoppedAtStage());
        lines.add("- What was attempted: " + text(outcome.whatWasAttempted()));
        lines.add("- Implementation conclusion: " + (outcome.implementationConclusion() == null
                ? FindingContextRenderer.NOT_PROVIDED : outcome.implementationConclusion()));
        lines.add("- Dependency validation result: " + (outcome.dependencyValidationStatus() == null
                ? FindingContextRenderer.NOT_PROVIDED : outcome.dependencyValidationStatus()));
        lines.add("- Full build result: " + (outcome.fullBuildValidationStatus() == null
                ? FindingContextRenderer.NOT_PROVIDED : outcome.fullBuildValidationStatus()));
        lines.add("- Exact failure reason: " + text(outcome.failureReason()));
        lines.add("- Rollback succeeded: " + outcome.rollbackSucceeded());
        lines.add("- Cumulative state after rejection: " + text(outcome.cumulativeStateAfterRejection()));
        lines.add("- Pipeline continued to the next group: " + outcome.pipelineContinued());
        lines.add("");
        appendList(lines, "What changed, as far as is known", outcome.whatChanged());
        appendList(lines, "Remaining work the implementation itself noted", outcome.remainingWork());
        appendList(lines, "Risks the implementation itself noted", outcome.risks());
    }

    /**
     * A bot-owned, structured account of a cohort-level final-integration Jenkins failure -- every group
     * in the cohort was individually accepted, but the fully assembled branch failed together. No-op when
     * this review is not about that shape at all. Never singles out one group as "the" cause -- the
     * {@code attributionNote} is rendered verbatim, exactly as {@link
     * com.tungsten.depbot.remediation.CohortIntegrationFailureOutcome} itself states it.
     */
    void appendCohortIntegrationFailure(List<String> lines, HumanReviewContext context) {
        if (!context.hasCohortIntegrationFailure()) {
            return;
        }
        com.tungsten.depbot.remediation.CohortIntegrationFailureOutcome outcome = context.cohortIntegrationFailure();
        lines.add("## Why the whole cohort could not be published");
        lines.add("");
        lines.add("- Branch: " + text(outcome.branchName()));
        lines.add("- Verified source ref: " + text(outcome.verifiedSourceRef()));
        lines.add("- Verified source SHA (S0): " + text(outcome.verifiedSourceSha()));
        lines.add("- Accepted groups: " + (outcome.acceptedGroupIds().isEmpty()
                ? FindingContextRenderer.NOT_PROVIDED : String.join(", ", outcome.acceptedGroupIds())));
        lines.add("- Failure reason: " + text(outcome.failureReason()));
        lines.add("- Attribution: " + text(outcome.attributionNote()));
        lines.add("");
        appendJenkinsFacts(lines, "The final integration Jenkins gate on the fully assembled branch failed:",
                outcome.integrationJenkinsValidation());
        appendList(lines, "Each accepted group's own already-passed validation, for context",
                outcome.perGroupValidationSummaries());
        lines.add("Reproduction instructions:");
        lines.add("");
        lines.add(text(outcome.reproductionInstructions()));
        lines.add("");
    }

    private static void appendJenkinsFacts(List<String> lines, String intro, JenkinsValidationOutcome outcome) {
        lines.add(intro);
        lines.add("");
        lines.add("- Status: " + outcome.status());
        lines.add("- Job: " + outcome.jobName());
        lines.add("- Build number: " + (outcome.buildNumber() == null ? FindingContextRenderer.NOT_PROVIDED
                : outcome.buildNumber()));
        lines.add("- Build URL: " + (outcome.buildUrl() == null || outcome.buildUrl().isBlank()
                ? FindingContextRenderer.NOT_PROVIDED : outcome.buildUrl()));
        lines.add("- Baseline SHA: " + outcome.baselineSha());
        lines.add("- Candidate SHA: " + outcome.candidateSha());
        lines.add("- Expected tree SHA: " + outcome.expectedTreeSha());
        lines.add("- Result: " + outcome.resultSummary());
        lines.add("");
    }

    private static void appendList(List<String> lines, String heading, List<String> values) {
        lines.add(heading + ":");
        lines.add("");
        if (values.isEmpty()) {
            lines.add("- " + FindingContextRenderer.NOT_PROVIDED);
        } else {
            for (String value : values) {
                lines.add("- " + value);
            }
        }
        lines.add("");
    }

    private static void appendAuthority(List<String> lines) {
        lines.add("## What you may and may not do");
        lines.add("");
        lines.add("- You have full read access and a full developer environment: any file in the working "
                + "tree, an unrestricted shell, and web search/fetch for an advisory or a compatibility "
                + "question -- whatever answering the six questions below genuinely needs.");
        lines.add("- **You cannot change anything.** Editing and writing are not available to you, and "
                + "nothing you do here is ever staged or committed.");
        lines.add("- Never open, quote, echo or record the contents of `.env`, `.env.local`, credential "
                + "files, private keys, keystores, or anything else holding a secret or token.");
        lines.add("");
    }

    private static void appendExpectedOutput(List<String> lines) {
        lines.add("## What to return");
        lines.add("");
        lines.add("Write up your reasoning however is clearest -- it is read by a person, and it is kept. "
                + "Then end your answer with a single fenced `json` block containing exactly this document, "
                + "and nothing after it:");
        lines.add("");
        lines.add("```json");
        lines.add(OUTPUT_SCHEMA);
        lines.add("```");
        lines.add("");
        lines.add("`coordinates`, `vulnerabilitySummary`, `whyVulnerable`, `dependencyOrigin`, "
                + "`recommendedChange` and `validationApproach` are always required. Use `openQuestions` for "
                + "anything you genuinely could not establish, rather than filling it in to look complete.");
    }

    private String text(String value) {
        return findingRenderer.text(value);
    }
}
