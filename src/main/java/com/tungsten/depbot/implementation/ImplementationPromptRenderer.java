package com.tungsten.depbot.implementation;

import com.tungsten.depbot.assessment.AnalysisAttemptSummary;
import com.tungsten.depbot.assessment.AnalysisRemediationGroup;
import com.tungsten.depbot.assessment.FindingAssessment;
import com.tungsten.depbot.assessment.FindingContextRenderer;
import com.tungsten.depbot.assessment.PartialAnalysisState;
import com.tungsten.depbot.assessment.PlannedDependencyChange;
import com.tungsten.depbot.claude.ClaudePhase;
import com.tungsten.depbot.report.SecretRedactor;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Renders the implementation prompt: a remediation handed to the developer who will carry it out.
 *
 * <p><strong>The assessment is given as engineering context, not as a script.</strong> The plan is
 * reproduced because it is the reasoning of a colleague who studied the problem and is worth taking
 * seriously -- but it was written against a different checkout, and this prompt says so plainly. Following
 * it step by step while the branch says otherwise is the failure mode being designed out, so the prompt
 * asks for the remediation to be done correctly, not for the plan to be executed.
 *
 * <p><strong>No list of permitted files or changes.</strong> A dependency security fix can turn out to be
 * a version property, a BOM import, a transitive exclusion, a compatibility change across several source
 * files and their tests, regenerated licence metadata, or some combination nobody predicted. Enumerating
 * what may be touched would either forbid the correct fix or amount to a checklist; what the change is
 * allowed to be is instead judged afterwards, on the diff, before anything is committed.
 *
 * <p>Every Mend-authored string passes through a {@link SecretRedactor}, since this prompt is written to
 * disk as {@code prompt.md}.
 */
public final class ImplementationPromptRenderer {

    /** The document the implementation must return. Field names match {@link ImplementationReport}. */
    static final String OUTPUT_SCHEMA = """
            {
              "schemaVersion": "1.0",
              "coordinates": "groupId:artifactId you worked on",
              "conclusion": "COMPLETED | STOPPED_ASSESSMENT_CONTRADICTED | STOPPED_BLOCKED | STOPPED_PLAN_DEVIATION_REQUIRED",
              "summary": "what you did, or why you stopped",
              "observedState": "what you actually found on this branch, in your own words",
              "changesMade": ["each change you made and why it was needed"],
              "divergenceFromAssessment": ["anything the branch showed that the assessment got wrong"],
              "validationPerformed": ["what you checked, and what it showed"],
              "remainingWork": ["ONLY concrete, unfinished, mandatory human actions that block merge/release -- see below"],
              "risks": ["risks and caveats a reviewer should know about"]
            }""";

    private final SecretRedactor redactor;
    private final FindingContextRenderer findingRenderer;

    /** A renderer that knows no secrets. Only for callers that genuinely hold none. */
    public ImplementationPromptRenderer() {
        this(SecretRedactor.none());
    }

    public ImplementationPromptRenderer(SecretRedactor redactor) {
        this.redactor = Objects.requireNonNull(redactor, "redactor");
        this.findingRenderer = new FindingContextRenderer(redactor);
    }

    public String render(ImplementationContext context) {
        Objects.requireNonNull(context, "context");

        if (context.partialAnalysisState() != null) {
            return renderPartialAnalysisFallback(context);
        }

        List<String> lines = new ArrayList<>();
        lines.add(ClaudePhase.IMPLEMENTATION.promptMarker());
        lines.add("");
        lines.add("# Security remediation: " + context.coordinates());
        lines.add("");
        appendRole(lines, context);
        appendBranch(lines, context);
        for (int i = 0; i < context.members().size(); i++) {
            ImplementationGroupMember member = context.members().get(i);
            if (!context.isSingleMember()) {
                lines.add("## Finding " + (i + 1) + " of " + context.members().size() + ": "
                        + member.coordinates());
                lines.add("");
            }
            findingRenderer.appendTo(lines, member.workItem());
            appendFindingConclusion(lines, member.findingAssessment());
        }
        appendGroupPlan(lines, context.group());
        if (context.repairContext() != null) {
            appendRepairEvidence(lines, context.repairContext());
        }
        appendCompanions(lines, context);
        appendAuthority(lines);
        appendTimeBudget(lines);
        appendStopRule(lines);
        appendPlanDeviationStopRule(lines);
        appendRemainingWorkContract(lines);
        appendExpectedOutput(lines);

        return redactor.redact(String.join("\n", lines) + "\n");
    }

    /**
     * The constrained fallback prompt used only when Vulnerability Analysis could not complete after two
     * attempts (see {@code VulnerabilityRemediationService}'s partial-analysis fallback). There is no
     * engineered plan here to reproduce -- only Mend's own raw finding data (never anything Java or this
     * class invented) and whatever partial evidence the two analysis attempts actually left behind.
     *
     * <p><strong>This is the one place the boundary between Vulnerability Analysis and the Remediation
     * Engineer is spelled out explicitly, rather than assumed from the shape of a completed
     * assessment.</strong> The call is authorised to determine <em>only</em> the specific technical
     * changes needed to carry out an upgrade direction that is already reliably established -- which
     * file, property or reference actually needs to change -- never to conduct new vulnerability research,
     * pick a different target version, invent an alternative remediation strategy, or decide CVE
     * applicability. {@code STOPPED_BLOCKED} is not a lesser outcome here: it is the correct, expected
     * answer whenever the call cannot confidently tell what specific change is already established, and
     * this prompt says so plainly rather than leaving that judgement to be inferred.
     */
    private String renderPartialAnalysisFallback(ImplementationContext context) {
        ImplementationGroupMember member = context.members().get(0);
        PartialAnalysisState partial = context.partialAnalysisState();

        List<String> lines = new ArrayList<>();
        lines.add(ClaudePhase.IMPLEMENTATION.promptMarker());
        lines.add("");
        lines.add("# Security remediation (partial-analysis fallback): " + context.coordinates());
        lines.add("");
        lines.add("You are the senior Java developer implementing this security remediation. This one is "
                + "different from an ordinary call: **Vulnerability Analysis could not reach a conclusion "
                + "for this finding after two attempts**, both of which ran out of turns or time. There is "
                + "no colleague's engineered plan below -- only Mend's own raw report on this finding, and "
                + "whatever partial evidence the two analysis attempts actually left behind.");
        lines.add("");
        lines.add("**Your job here is narrow, and it is not to finish the vulnerability research yourself.** "
                + "You may determine, and only determine, the specific technical changes needed to carry "
                + "out an upgrade direction that is already reliably established from what is given below "
                + "-- for example, which property or version reference in the build actually needs to "
                + "change, which related files or third-party notices reference the same version, and "
                + "exactly which lines to edit. You must not: conduct new vulnerability or advisory "
                + "research, decide CVE applicability, pick a target version other than the one already "
                + "established below, invent an alternative remediation strategy, or fold in an unrelated "
                + "dependency. If what is given below does not let you confidently tell what specific "
                + "change is already established, **do not guess** -- stop with `STOPPED_BLOCKED` and say "
                + "plainly that the direction could not be determined from the partial analysis. That is "
                + "the correct, expected outcome here, not a failure, and it is exactly what routes this "
                + "finding to a person instead of an invented decision.");
        lines.add("");
        appendBranch(lines, context);
        findingRenderer.appendTo(lines, member.workItem());
        appendPartialAnalysisEvidence(lines, partial);
        appendAuthority(lines);
        appendTimeBudget(lines);
        appendPartialAnalysisStopRule(lines);
        appendRemainingWorkContract(lines);
        appendExpectedOutput(lines);

        return redactor.redact(String.join("\n", lines) + "\n");
    }

    /** Whatever either Vulnerability Analysis attempt actually established -- never presented as a conclusion. */
    private void appendPartialAnalysisEvidence(List<String> lines, PartialAnalysisState partial) {
        lines.add("## What the two Vulnerability Analysis attempts actually established");
        lines.add("");
        lines.add("Neither attempt reached a validated conclusion. What follows is raw, unverified output "
                + "from each -- read it as leads to check against the branch yourself, never as an "
                + "established fact.");
        lines.add("");
        appendAttemptEvidence(lines, "First attempt", partial.attempt1());
        appendAttemptEvidence(lines, "Second attempt", partial.attempt2());
    }

    private void appendAttemptEvidence(List<String> lines, String label, AnalysisAttemptSummary attempt) {
        lines.add("### " + label + " (" + attempt.invocation().outcomeReason() + ")");
        lines.add("");
        if (attempt.hasRawResultText()) {
            lines.add(text(attempt.rawResultText()).strip());
        } else {
            lines.add("Nothing survived from this attempt -- it was stopped before it produced any usable "
                    + "output at all.");
        }
        lines.add("");
    }

    private static void appendPartialAnalysisStopRule(List<String> lines) {
        lines.add("## If the direction cannot be confidently determined");
        lines.add("");
        lines.add("Stop. Do not guess a target version, and do not invent a remediation strategy. If Mend's "
                + "own report and the partial analysis evidence above do not let you confidently tell what "
                + "specific upgrade this finding needs, or if what you find on the branch contradicts them "
                + "-- the dependency is not present, already at a fixed version, or the only version "
                + "mentioned would be a downgrade or does not exist -- set `conclusion` to "
                + "`STOPPED_BLOCKED`, explain what you could and could not establish in `risks` or "
                + "`remainingWork`, and change nothing. This routes the finding to a person, which is "
                + "exactly the right outcome when the direction genuinely cannot be determined safely.");
        lines.add("");
    }

    private static void appendRole(List<String> lines, ImplementationContext context) {
        lines.add("You are the senior Java developer implementing this security remediation.");
        lines.add("");
        if (context.isSingleMember()) {
            lines.add("A colleague has already assessed the problem and their assessment is below. A branch "
                    + "has been prepared for you from the commit git resolved for the ref they identified. "
                    + "Your job is to remediate this finding correctly on that branch.");
        } else {
            lines.add("This call covers " + context.members().size() + " findings, not one. A colleague "
                    + "assessed each of them, and at least one assessment concluded they cannot be "
                    + "remediated safely in isolation -- so all of them are handed to you together, on one "
                    + "branch prepared from the commit git resolved for the ref every one of their "
                    + "assessments agreed on. Your job is to work out one coherent remediation across all "
                    + "of them; how the fixes actually relate is yours to determine, not something the "
                    + "assessments below fully worked out in advance.");
        }
        lines.add("");
        lines.add("**The assessment below is already the product of investigation.** A colleague already did "
                + "the dependency, security and compatibility analysis this finding needed -- their "
                + "implementation plan, evidence and validation plan are what you work from, not a starting "
                + "point to independently re-derive. Your job is to apply the remediation, not to redo the "
                + "analysis that already produced it.");
        lines.add("");
        lines.add("**Before you change anything, check only the minimal facts the plan depends on.** "
                + "The assessment was written from a different checkout, so confirm the handful of things "
                + "that would matter if it were wrong -- the dependency is where and how it described, the "
                + "observed version is consistent with what is actually there, and the recommended target is "
                + "not already in place, not a downgrade, and genuinely exists. That is a targeted check "
                + "against the plan's own claims, not a fresh investigation of the whole problem. If nothing "
                + "you find contradicts the assessment, move straight to making the edit.");
        lines.add("");
        lines.add("The plan is a colleague's reasoning, not a script you are being measured against: once you "
                + "are actually editing, if your own reading of the branch calls for something different, do "
                + "the right thing and say so in your report. That is a reason to adjust the edit in front of "
                + "you, not a license to go back and re-investigate everything from the start.");
        lines.add("");
        lines.add("**Your budget's priority is the edit, then the targeted validation it needs, then your "
                + "report -- in that order, not a repeat of the assessment's own analysis.** Go beyond the "
                + "minimal check above only when editing or validating actually turns up something concrete: "
                + "a real contradiction with the assessment, or a specific blocker standing in the way of "
                + "finishing. That is what further investigation is for here -- resolving a problem you have "
                + "actually hit, not routine first-step re-analysis.");
        lines.add("");
    }

    private void appendBranch(List<String> lines, ImplementationContext context) {
        lines.add("## The branch you are on");
        lines.add("");
        lines.add("- You are already running with your working directory set to the repository: "
                + context.workspace() + ".");
        lines.add("- Branch: `" + context.branchName() + "`, already checked out for you.");
        lines.add("- It was created from " + context.branchBaseSha() + ", which is the commit git resolved "
                + "for `" + text(context.verifiedSourceRef()) + "` -- the ref the assessment identified. "
                + "That resolution was done by this bot against the repository, not taken from the "
                + "assessment.");
        lines.add("- The branch is yours alone for this remediation. Nothing else is working on it.");
        lines.add("");
    }

    /** What this one finding's own conclusion said -- everything genuinely specific to it alone. */
    private void appendFindingConclusion(List<String> lines, FindingAssessment findingAssessment) {
        lines.add("Conclusion from the colleague who investigated this finding. Weigh it; do not obey it.");
        lines.add("");
        lines.add("- Conclusion: " + findingAssessment.conclusion());
        lines.add("- Summary: " + text(findingAssessment.summary()));
        lines.add("");
        appendList(lines, "What they established, and how", findingAssessment.evidence());
        appendList(lines, "Risks and unknowns they flagged", findingAssessment.risks());
    }

    /**
     * The remediation group's own shared plan -- rendered once, not per finding, since it describes one
     * coordinated change covering every member of the group together, not a separate decision per member.
     *
     * <p><strong>This plan is a binding execution contract, not context to weigh.</strong> The
     * Vulnerability Analysis Engineer already investigated this remediation; its narrative reasoning and
     * the concrete {@link PlannedDependencyChange}s below are what this call carries out, not a starting
     * point to independently re-derive or improve on.
     */
    private void appendGroupPlan(List<String> lines, AnalysisRemediationGroup group) {
        lines.add("## The remediation plan (binding execution contract)");
        lines.add("");
        lines.add("**This plan is a binding execution contract, not a suggestion.** A colleague already "
                + "investigated this remediation; their narrative reasoning and the concrete dependency "
                + "changes below are what you carry out. You must not choose a different target version, a "
                + "different remediation strategy, or make substantive changes this plan does not call "
                + "for.");
        lines.add("");
        lines.add("**If you discover during implementation that this plan is incomplete or wrong** -- the "
                + "target version does not exist, the described change does not apply the way the plan "
                + "says, or the remediation genuinely needs a different strategy -- **stop. Do not "
                + "improvise a fix.** Undo whatever partial edits you made, set `conclusion` to "
                + "`STOPPED_PLAN_DEVIATION_REQUIRED`, and explain plainly in `risks` or `remainingWork` what "
                + "is wrong with the plan and why. Only report `COMPLETED` if you followed this plan as "
                + "written.");
        lines.add("");
        lines.add("- Why these findings belong together: " + text(group.groupingReason()));
        lines.add("- Ref assessed: " + text(group.sourceRef()));
        lines.add("- How the dependency was thought to arrive: " + text(group.origin() == null
                ? null : group.origin().name()));
        lines.add("- Relationship: " + text(group.dependencyRelationship()));
        lines.add("- Version they observed: " + text(group.observedVersion()));
        lines.add("- Remediation they recommend: " + text(group.recommendedRemediation()));
        lines.add("- Target version they recommend: " + text(group.recommendedTargetVersion()));
        lines.add("- Size they scored it at: " + (group.hasImpactScore()
                ? group.impactScore().value() + " (" + group.impactScore().description() + ")"
                : FindingContextRenderer.NOT_PROVIDED));
        lines.add("- Why that size: " + text(group.impactReason()));
        lines.add("");
        appendList(lines, "Files they expected to be involved", group.affectedFiles());
        appendList(lines, "Their implementation plan", group.implementationPlan());
        appendList(lines, "Their validation plan", group.validationPlan());
        appendPlannedChanges(lines, group.plannedChanges());
    }

    /**
     * The plan's machine-readable {@link PlannedDependencyChange}s, listed explicitly and individually --
     * these exact coordinate/version/file combinations are what is authorised, and what a later,
     * Java-owned conformance check re-verifies against the actual diff once you are done.
     */
    private void appendPlannedChanges(List<String> lines, List<PlannedDependencyChange> plannedChanges) {
        lines.add("Planned dependency changes -- exactly these coordinates, versions and files are "
                + "authorised, nothing else:");
        lines.add("");
        if (plannedChanges.isEmpty()) {
            lines.add("- " + FindingContextRenderer.NOT_PROVIDED);
        } else {
            for (PlannedDependencyChange change : plannedChanges) {
                lines.add("- " + text(change.dependencyCoordinates()) + ": "
                        + text(change.currentVersion()) + " -> " + text(change.targetVersion())
                        + " in `" + text(change.affectedFile()) + "` ("
                        + (change.changeType() == null ? FindingContextRenderer.NOT_PROVIDED
                                : change.changeType().name())
                        + "): " + text(change.reason()));
            }
        }
        lines.add("");
    }

    /**
     * The evidence this repair attempt (attempt 2) needs to fix a specific, already-diagnosed problem --
     * active only when {@link ImplementationContext#repairContext()} is non-null. Explicit that this is
     * not licence to re-investigate the finding from scratch or change the plan's own direction.
     */
    private void appendRepairEvidence(List<String> lines, RepairContext repair) {
        lines.add("## This is a repair attempt -- fix the specific problem below");
        lines.add("");
        lines.add("**Your previous attempt at this remediation did not succeed.** This is your one and "
                + "only repair attempt: do not re-investigate the finding from scratch, and do not change "
                + "the target version or remediation strategy the plan above already established. Fix the "
                + "specific problem described below, on this fresh branch prepared from the same starting "
                + "point as before.");
        lines.add("");
        lines.add("- Where the previous attempt stopped: " + repair.failedStage());
        lines.add("- What went wrong: " + text(repair.exactErrorEvidenceSummary()));
        lines.add("");
        if (repair.implementationDiff() != null && !repair.implementationDiff().isBlank()) {
            lines.add("Your previous attempt's diff, for reference (already undone -- the branch is clean "
                    + "again):");
            lines.add("");
            lines.add("```diff");
            lines.add(repair.implementationDiff());
            lines.add("```");
            lines.add("");
        }
        if (repair.dependencyValidationOutcome() != null) {
            lines.add("- Dependency-resolution gate: " + text(repair.dependencyValidationOutcome().reason()));
        }
        if (repair.fullBuildValidationOutcome() != null) {
            lines.add("- Full build: " + text(repair.fullBuildValidationOutcome().reason()));
        }
        if (repair.cumulativeJenkinsValidation() != null) {
            lines.add("- Cumulative Jenkins validation: "
                    + text(repair.cumulativeJenkinsValidation().resultSummary()));
        }
        if (repair.jenkinsConsoleLogExcerpt() != null && !repair.jenkinsConsoleLogExcerpt().isBlank()) {
            lines.add("");
            lines.add("Jenkins console log excerpt:");
            lines.add("");
            lines.add("```");
            lines.add(repair.jenkinsConsoleLogExcerpt());
            lines.add("```");
        }
        lines.add("");
        if (!repair.conformanceViolations().isEmpty()) {
            appendList(lines, "Plan-conformance violations a Java-owned structural check found",
                    repair.conformanceViolations());
        }
    }

    /**
     * The plan-deviation stop rule. Distinct from {@link #appendStopRule}, which is about the branch
     * disagreeing with the <em>assessment</em>; this is about the implementation itself discovering the
     * <em>plan</em> is wrong or incomplete once it is actually doing the work.
     */
    private static void appendPlanDeviationStopRule(List<String> lines) {
        lines.add("## If the approved plan itself is incomplete or wrong");
        lines.add("");
        lines.add("This is different from the branch contradicting the assessment above: here, the plan's "
                + "own strategy -- the target version, the specific change it describes, or its approach -- "
                + "turns out not to be right once you are actually doing the work. Do not pick a different "
                + "target version or invent an alternative strategy yourself. Stop, undo any partial edits, "
                + "set `conclusion` to `STOPPED_PLAN_DEVIATION_REQUIRED`, and explain plainly in `risks` or "
                + "`remainingWork` what is wrong with the plan and why -- this sends the group back through "
                + "planning with your findings, rather than leaving a change on the branch that quietly "
                + "diverged from what was approved.");
        lines.add("");
    }

    private void appendList(List<String> lines, String heading, List<String> values) {
        lines.add(heading + ":");
        lines.add("");
        if (values.isEmpty()) {
            lines.add("- " + FindingContextRenderer.NOT_PROVIDED);
        } else {
            for (String value : values) {
                lines.add("- " + text(value));
            }
        }
        lines.add("");
    }

    private static void appendCompanions(List<String> lines, ImplementationContext context) {
        if (context.companionCoordinates().isEmpty()) {
            return;
        }
        lines.add("## Related coordinates with no Mend finding of their own");
        lines.add("");
        lines.add("At least one assessment above named these as required alongside its own finding, even "
                + "though none of them has a Mend finding here. Take them into account when working out a "
                + "coherent fix -- the assessment that named them believed the remediation is incomplete "
                + "without them.");
        lines.add("");
        for (String companion : context.companionCoordinates()) {
            lines.add("- " + companion);
        }
        lines.add("");
    }

    private static void appendAuthority(List<String> lines) {
        lines.add("## What you may and may not do");
        lines.add("");
        lines.add("- **Change whatever this remediation genuinely requires.** Build configuration, POMs, a "
                + "BOM import or `dependencyManagement`, a version property, Java sources, tests, "
                + "resources, configuration, generated third-party or licence metadata, related "
                + "dependencies in the same family that have to move together, and any compatibility code "
                + "the new version needs. There is no POM-only or version-only restriction, and no limit "
                + "on how many files or modules you may touch.");
        lines.add("- The one boundary on scope is relevance: every change should be there because this "
                + "security remediation needs it. Unrelated cleanup, reformatting or opportunistic "
                + "refactoring does not belong in this change, not because it is forbidden in principle "
                + "but because it makes the security fix harder to review.");
        lines.add("- Do not delete or disable existing tests, and do not skip them. If a test genuinely has "
                + "to change because the library's behaviour changed, change it and say so in your report.");
        lines.add("- You have a full developer environment: an unrestricted shell (Maven, Java, `curl`, "
                + "package and archive tools, anything this remediation genuinely needs), and web "
                + "search/fetch for an advisory, a release note or a compatibility question. This is an "
                + "ordinary developer's toolbox, not a curated menu of pre-approved commands.");
        lines.add("- **Git is yours to use freely for local investigation and your own workflow** -- "
                + "`git diff`, `git log`, `git show`, `git blame`, `git status`, `git fetch`, "
                + "`git remote` and the rest, including `git commit` if that helps how you work. **What "
                + "is not yours is finishing the job with it.** The bot is what stages, reviews and "
                + "commits your change (or undoes it) once you report completion, based on what it finds "
                + "in the working tree -- so leave the remediation itself as ordinary, uncommitted "
                + "working-tree edits for the bot to pick up, rather than sealing it inside a commit only "
                + "you made. If you do commit anyway, the bot still finds and reviews exactly the same "
                + "change; you have not skipped anything, only added a step that did not help.");
        lines.add("- **You must never push.** It is refused at the tool level. Publishing anything at "
                + "all -- a branch, a tag, this commit or any other, a merge request, on this repository "
                + "or on any git host -- is never yours to do, with git or with any other tool, and "
                + "never will be.");
        lines.add("- Never open, quote, echo or record the contents of `.env`, `.env.local`, credential "
                + "files, private keys, keystores, or anything else holding a secret or token. If a file "
                + "looks like it holds one, leave it closed and reproduce nothing from it in your report.");
        lines.add("");
        lines.add("Environment notes: never run `cd` -- use a path in the command itself. Issue each Bash "
                + "command as its own single command, with no `&&`, `;`, `||`, pipes or redirection. Use the "
                + "Read, Glob, Grep, Edit and Write tools for files rather than shelling out.");
        lines.add("");
    }

    private static void appendTimeBudget(List<String> lines) {
        lines.add("## Manage your own time and turn budget");
        lines.add("");
        lines.add("You have both a turn budget and a wall-clock time budget for this call, and both are "
                + "generous, but neither is unlimited. Carry out the remediation as thoroughly as it "
                + "genuinely needs, but reserve enough of both to finish your edits and write your report -- "
                + "do not spend everything investigating or polishing and end up with an unfinished change "
                + "and nothing said about it. As a rough guide, once you sense you are past roughly three "
                + "quarters of either your turns or your time without a clear path to finishing, stop and "
                + "write up what is actually there rather than continuing to edit.");
        lines.add("");
        lines.add("Running out of room before you are confident the remediation is complete is not a "
                + "failure -- it is exactly the situation `STOPPED_BLOCKED` exists for. Report plainly what "
                + "you changed, what is still missing, and why, rather than leaving an unfinished edit with "
                + "nothing said about it. An honest, partial report is always more useful than silence, and "
                + "it is what lets a person pick up exactly where you left off.");
        lines.add("");
    }

    private static void appendStopRule(List<String> lines) {
        lines.add("## If the branch contradicts the assessment");
        lines.add("");
        lines.add("Stop. Do not force the plan through. This is exactly the concrete contradiction that "
                + "warrants going beyond the targeted check above -- not routine re-analysis, but working out "
                + "what a real disagreement with the assessment means for this remediation.");
        lines.add("");
        lines.add("If what you find here disproves the premise of the remediation -- the dependency is not "
                + "present, not present the way the assessment described, already at a fixed version, or "
                + "the recommended target would be a downgrade or does not exist -- then the right thing to "
                + "do is report that and change nothing. Say what you found and how it differs, and set "
                + "`conclusion` to `STOPPED_ASSESSMENT_CONTRADICTED`.");
        lines.add("");
        lines.add("This is a good outcome, not a failure, and it is why you were asked to check first. Any "
                + "edits you had already made before realising will be undone; you do not need to revert "
                + "anything yourself, and you must not use git to do so.");
        lines.add("");
        lines.add("A smaller disagreement is different. If the assessment was wrong about a detail but the "
                + "remediation is still the right thing to do, do it, record the disagreement in "
                + "`divergenceFromAssessment`, and finish with `COMPLETED`.");
        lines.add("");
    }

    /**
     * Strengthens the {@code remainingWork} contract -- a bot-owned report renders every non-empty
     * {@code remainingWork} as a blocking "Required human checks before merge" checklist, with a "do not
     * merge" recommendation (see {@code RemediationReportMarkdownRenderer}). That rendering only stays
     * honest if this field genuinely never carries anything but a true, unfinished, merge/release-blocking
     * human action (production defect, pilot {@code 20260909-061155-6ca4db}: an optional hardening
     * suggestion, and a note explaining why something was left as an uncommitted working-tree edit rather
     * than a commit-message rationale, both landed in {@code remainingWork} and were rendered as mandatory
     * merge blockers). Java only carries this field through verbatim -- it never filters, classifies or
     * pattern-matches its prose -- so the contract has to be enforced here, not downstream.
     */
    private static void appendRemainingWorkContract(List<String> lines) {
        lines.add("## What belongs in `remainingWork` -- and what does not");
        lines.add("");
        lines.add("`remainingWork` is rendered, verbatim, as a blocking checklist a human must complete "
                + "before this change may be merged or released -- never as a place for anything softer. "
                + "Before adding an item, it must answer yes to all of: is it a concrete action (not an "
                + "explanation or a note), is it genuinely unfinished, does it require a human specifically "
                + "(not something you could have done yourself), and would you actually block merge/release "
                + "on it not being done? If the honest answer to any of those is no, it does not belong "
                + "here, however worth mentioning it still is elsewhere.");
        lines.add("");
        lines.add("Route it correctly instead:");
        lines.add("");
        lines.add("- An optional recommendation, a nice-to-have, or hardening you deliberately chose not to "
                + "do now -> `risks`, or say so in your narrative summary. Never `remainingWork` merely "
                + "because it is worth someone's attention -- optional means it does not block anything.");
        lines.add("- A residual risk with no concrete action attached to it -> `risks`.");
        lines.add("- An explanation of why you left something as an uncommitted working-tree edit, why a "
                + "commit message says what it says, or any other rationale for a choice you already made "
                + "-> your narrative summary or `divergenceFromAssessment`, never `remainingWork` -- that "
                + "field is for what is still undone, not for commentary on what you already did.");
        lines.add("- Historical context, or an action that was already completed by some other means -> "
                + "`validationPerformed` or your summary, not `remainingWork`.");
        lines.add("");
        lines.add("**If there is no genuinely mandatory, unfinished human action, `remainingWork` must be "
                + "an empty list.** An empty `remainingWork` is a normal, good outcome, not something to "
                + "fill in for the sake of having an answer.");
        lines.add("");
        lines.add("For example (illustrative only, not a real remediation): \"Run SAML SSO against the "
                + "test IdP over HTTPS and verify an untrusted certificate is rejected before merge\" is a "
                + "genuine `remainingWork` item -- concrete, unfinished, human-only, and merge-blocking. "
                + "\"Optional hardening: consider enabling X\", \"Document why version Y is safe\", \"This "
                + "was intentionally left unchanged\", and \"Review if desired\" are not -- none of them "
                + "names a mandatory action that actually blocks merge or release.");
        lines.add("");
    }

    private static void appendExpectedOutput(List<String> lines) {
        lines.add("## What to return");
        lines.add("");
        lines.add("Write up what you did however is clearest -- it is read by people, and it is kept. Then "
                + "end your answer with a single fenced `json` block containing exactly this document, and "
                + "nothing after it:");
        lines.add("");
        lines.add("```json");
        lines.add(OUTPUT_SCHEMA);
        lines.add("```");
        lines.add("");
        lines.add("`coordinates`, `conclusion`, `summary` and `observedState` are always required. A "
                + "`COMPLETED` conclusion must list `changesMade`. A `STOPPED_ASSESSMENT_CONTRADICTED` "
                + "conclusion must list `divergenceFromAssessment`. A `STOPPED_BLOCKED` conclusion must "
                + "carry `risks` or `remainingWork`. A `STOPPED_PLAN_DEVIATION_REQUIRED` conclusion must "
                + "likewise carry `risks` or `remainingWork`, explaining what was wrong with the plan. "
                + "Leave anything else out rather than filling it in to look complete.");
        lines.add("");
        lines.add("Your report is what decides whether your work is kept: this bot commits the change only "
                + "on a `COMPLETED` conclusion, and only after checking the diff. Reporting completion you "
                + "are not confident in does not get the change accepted -- it gets an unreviewed change "
                + "onto a branch with a report that misdescribes it.");
    }

    private String text(String value) {
        return findingRenderer.text(value);
    }
}
