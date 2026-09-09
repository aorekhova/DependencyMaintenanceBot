package com.tungsten.depbot.assessment;

import com.tungsten.depbot.claude.ClaudePhase;
import com.tungsten.depbot.report.SecretRedactor;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Renders the whole-batch analysis prompt: every Mend finding in one run, handed at once to the
 * Vulnerability Analysis Engineer.
 *
 * <p><strong>This prompt deliberately contains no investigation procedure</strong>, for exactly the
 * reason {@code DeveloperAssessmentPromptRenderer} (the per-finding renderer this replaces) documented:
 * a prescriptive procedure cannot accommodate a finding turning out to belong to a different branch, or
 * a coupling between findings nobody predicted. Seeing every finding in the run at once is what lets
 * Claude notice a real technical coupling between two of them -- but noticing one is still its own
 * engineering judgement, not something this prompt walks it toward. It is told what a remediation group
 * is and why the bot needs one, never how many to expect or which findings are likely to share one.
 *
 * <p>Every piece of Mend-authored text passes through a {@link SecretRedactor}, the same as the prompt
 * this replaces.
 */
public final class BatchAnalysisPromptRenderer {

    /**
     * The document the analysis must return. Field names match {@link BatchAnalysis},
     * {@link FindingAssessment} and {@link AnalysisRemediationGroup} exactly.
     */
    static final String OUTPUT_SCHEMA = """
            {
              "schemaVersion": "1.0",
              "findings": [
                {
                  "coordinates": "groupId:artifactId this finding is about",
                  "vulnerabilityIds": ["the CVEs this covers"],
                  "summary": "what you concluded about this finding, in a few sentences",
                  "conclusion": "REMEDIATION_REQUIRED | NO_ACTION_REQUIRED | INCONCLUSIVE",
                  "remediationGroupId": "the groupId below this finding belongs to, only when REMEDIATION_REQUIRED",
                  "evidence": ["what you actually established, and what showed it"],
                  "risks": ["risks, caveats and anything you could not establish"],
                  "noActionBasis": "DEPENDENCY_NOT_PRESENT | NO_FIXED_VERSION_EXISTS | ALREADY_AT_OR_ABOVE_FIXED_VERSION, only when conclusion is NO_ACTION_REQUIRED"
                }
              ],
              "remediationGroups": [
                {
                  "groupId": "a name you choose, unique within this analysis",
                  "memberCoordinates": ["every finding's groupId:artifactId that points at this group"],
                  "companionCoordinates": ["dependencies with no finding of their own that must move with this group"],
                  "groupingReason": "why these belong together (or why this one stands alone)",
                  "sourceRef": "the ref you concluded is affected, e.g. origin/release/9.2, or null",
                  "sourceCommitSha": "the commit you believe that ref is at, or null",
                  "origin": "DIRECT | TRANSITIVE | PROPERTY | DEPENDENCY_MANAGEMENT | BOM | ABSENT | UNKNOWN",
                  "dependencyRelationship": "how it actually arrives and what controls its version, or null",
                  "observedVersion": "the version genuinely present on sourceRef, or null",
                  "recommendedRemediation": "what should be done, in your words",
                  "recommendedTargetVersion": "the version to move to, or null if that is not the fix",
                  "affectedFiles": ["files you concluded are involved"],
                  "impactScore": 1,
                  "impactReason": "why that score and not one either side of it",
                  "automationSafety": "AUTOMATIC_ALLOWED | HUMAN_REVIEW_REQUIRED",
                  "automationSafetyReason": "why this is safe (or not) to trust to automation",
                  "implementationPlan": ["the steps you would carry out, in order"],
                  "validationPlan": ["how the result should be checked"],
                  "plannedChanges": [
                    {
                      "dependencyCoordinates": "groupId:artifactId this specific edit is about",
                      "currentVersion": "the version currently in effect, or null",
                      "targetVersion": "the version this edit moves it to, or null when this is not a version bump",
                      "affectedFile": "the exact file this edit must land in, e.g. pom.xml",
                      "changeType": "VERSION_BUMP | DEPENDENCY_MANAGEMENT_ADDITION | EXCLUSION_ADDED | OTHER",
                      "reason": "why this specific edit, in your words"
                    }
                  ]
                }
              ]
            }""";

    private final SecretRedactor redactor;
    private final FindingContextRenderer findingRenderer;

    /** A renderer that knows no secrets. Only for callers that genuinely hold none. */
    public BatchAnalysisPromptRenderer() {
        this(SecretRedactor.none());
    }

    public BatchAnalysisPromptRenderer(SecretRedactor redactor) {
        this.redactor = Objects.requireNonNull(redactor, "redactor");
        this.findingRenderer = new FindingContextRenderer(redactor);
    }

    public String render(AnalysisContext context) {
        Objects.requireNonNull(context, "context");
        List<VulnerabilityWorkItem> workItems = context.workItems();

        List<String> lines = new ArrayList<>();
        lines.add(ClaudePhase.ASSESSMENT.promptMarker());
        lines.add("");
        lines.add("# Security dependency findings: " + workItems.size()
                + (workItems.size() == 1 ? " finding" : " findings") + " to investigate together");
        lines.add("");
        appendRole(lines, workItems.size());
        for (int i = 0; i < workItems.size(); i++) {
            lines.add("## Finding " + (i + 1) + " of " + workItems.size() + ": " + workItems.get(i).coordinates());
            lines.add("");
            findingRenderer.appendTo(lines, workItems.get(i));
        }
        appendRepository(lines, context);
        appendAuthority(lines);
        appendInvestigationBudget(lines);
        appendImpactScale(lines);
        appendAutomationSafety(lines);
        appendLifecycleWording(lines);
        appendGrouping(lines);
        appendNoActionRequiredStandard(lines);
        appendVersionRangeWording(lines);
        appendPlannedChanges(lines);
        appendExpectedOutput(lines);

        return redactor.redact(String.join("\n", lines) + "\n");
    }

    private static void appendRole(List<String> lines, int findingCount) {
        lines.add("You are the senior Java developer responsible for resolving every one of the "
                + findingCount + " security dependency findings above correctly.");
        lines.add("");
        lines.add("Investigate the repository, its build configuration, its dependency relationships, its "
                + "Git history, the refs available to you, and the Mend evidence above -- as deeply as each "
                + "finding genuinely needs. Then work out, for each one, what the correct remediation "
                + "actually is, and which findings -- if any -- must be remediated together rather than "
                + "each on its own.");
        lines.add("");
        lines.add("**Do not assume any of the following is true.** Each has already been wrong in practice:");
        lines.add("");
        lines.add("- that the branch currently checked out is the one any given finding affects;");
        lines.add("- that the target version this bot computed is correct, or is even an upgrade;");
        lines.add("- that the location or version Mend reported is where the dependency really comes from;");
        lines.add("- that the dependency is present in this repository at all;");
        lines.add("- that two findings are unrelated just because they were reported separately, or that "
                + "two findings are related just because they were handed to you together.");
        lines.add("");
        lines.add("Use your engineering judgment to determine where each problem actually exists, what the "
                + "correct remediation is, how invasive it will be, how it should be validated, and how the "
                + "findings relate to one another. You are responsible for producing a defensible "
                + "engineering analysis, not for following a predefined checklist -- nothing here prescribes "
                + "an order of investigation, a set of commands, or which files to look at, and nothing here "
                + "prescribes how many findings should end up sharing a remediation group. How you establish "
                + "the facts, and how you group them, is yours to decide.");
        lines.add("");
        lines.add("If the honest answer for a finding is that it does not apply here, or that something you "
                + "would need could not be established, say so and show what you checked. A well-evidenced "
                + "\"no action required\", or a clearly stated unknown, is a better answer than a confident "
                + "guess -- and it is treated as a real result, not a failure.");
        lines.add("");
    }

    private void appendRepository(List<String> lines, AnalysisContext context) {
        lines.add("## This repository");
        lines.add("");
        lines.add("- You are already running with your working directory set to the repository: "
                + context.workspace() + ".");
        lines.add("- Currently checked out: " + text(context.currentBranch()) + " at "
                + text(context.currentHeadSha()) + ". This is simply where the checkout happened to be; "
                + "it carries no implication that it is the ref any of these findings concern.");
        if (context.remoteRefsRefreshed()) {
            lines.add("- Remote refs were refreshed immediately before this call, so `origin/*` reflects "
                    + "the remote's branches and tags as they are now. Every remote branch and tag is "
                    + "yours to inspect directly, with your own git commands.");
        } else {
            lines.add("- Remote refs were **not** refreshed before this call, so `origin/*` may be out of "
                    + "date. Take that into account in what you conclude.");
        }
        lines.add("");
    }

    private static void appendAuthority(List<String> lines) {
        lines.add("## What you may and may not do");
        lines.add("");
        lines.add("- You have full read access and a full developer environment: any file in the working "
                + "tree, an unrestricted shell (Maven, Java, `curl`, package and archive tools, anything a "
                + "real investigation needs), and web search/fetch for an advisory or a compatibility "
                + "question. This is an ordinary developer's toolbox, not a curated menu of pre-approved "
                + "commands.");
        lines.add("- **Git is yours to use freely for investigation.** `git log`, `git show`, `git diff`, "
                + "`git grep`, `git blame`, `git for-each-ref` and the rest of local git are simply "
                + "available -- reading a file at another ref without checking it out, for example with "
                + "`git show <ref>:pom.xml`, is exactly what these are for.");
        lines.add("- **You cannot change anything in this phase.** Editing and writing are not available "
                + "to you; carrying out a remediation is a separate, later call made only after this "
                + "analysis has been reviewed by the bot.");
        lines.add("- **Do not switch or create branches, and do not stage, commit or reset anything.** "
                + "Git itself will let you -- this is not enforced as a tool restriction -- but there is "
                + "one managed checkout shared by the whole run, and changing what is checked out or "
                + "committed here would break work that is not yours. Investigate with git; do not use "
                + "it to move or alter the checkout. The bot independently checks the checkout again "
                + "after this call and puts it back if it finds otherwise, so nothing here relies on you "
                + "remembering this -- but doing it anyway only costs both of us time.");
        lines.add("- **You must never push.** It is refused at the tool level. Publishing anything at "
                + "all -- a branch, a tag, a commit, a merge request, on this repository or on any git "
                + "host -- is never yours to do, with git or with any other tool. `git fetch` and "
                + "`git remote` are otherwise available to you like the rest of local git, but "
                + "refreshing `origin/*` for the run as a whole is still the bot's own single, "
                + "deliberate step, already done before this call.");
        lines.add("- Never open, quote, echo or record the contents of `.env`, `.env.local`, credential "
                + "files, private keys, keystores, or anything else holding a secret or token. If a file "
                + "looks like it holds one, leave it closed and reproduce nothing from it in your answer.");
        lines.add("");
        lines.add("Environment notes: never run `cd` -- use a path in the command itself. Issue each Bash "
                + "command as its own single command, with no `&&`, `;`, `||`, pipes or redirection. Use "
                + "the Read, Glob and Grep tools for files rather than shelling out to `cat`, `find` or "
                + "`ls`.");
        lines.add("");
    }

    private static void appendInvestigationBudget(List<String> lines) {
        lines.add("## Manage your own investigation budget");
        lines.add("");
        lines.add("You have both a turn budget and a wall-clock time budget for this call, and both are "
                + "generous, but neither is unlimited, and this call covers every finding above, not one. "
                + "Investigate each finding as deeply as it genuinely needs, but reserve enough of both to "
                + "write up your conclusions for all of them -- do not spend everything on the first few "
                + "findings and end up with nothing left to answer with for the rest. As a rough guide, "
                + "once you sense you are past roughly three quarters of either your turns or your time "
                + "without having reached a clear answer for every finding yet, stop investigating now and "
                + "write up your best-effort analysis from whatever you have already established -- do not "
                + "wait for a system signal that time is up, since by then there may be no room left to "
                + "answer at all.");
        lines.add("");
        lines.add("Running out of room before you would otherwise be done is not a failure -- it is exactly "
                + "the situation `INCONCLUSIVE` and `risks` exist for. For any finding you did not reach, say "
                + "so plainly rather than leaving it out of your answer entirely: a bot that receives no "
                + "conclusion at all for a finding cannot tell \"there was genuinely nothing wrong\" apart "
                + "from \"there was no time left to look at it\" -- an honest, partial answer for every "
                + "finding is always more useful than silence for some of them.");
        lines.add("");
    }

    private static void appendImpactScale(List<String> lines) {
        lines.add("## Score the size of what each remediation group would involve");
        lines.add("");
        lines.add("For each remediation group, rate the change its plan would actually involve, from 1 to 10:");
        lines.add("");
        lines.add("```");
        lines.add(ImpactScore.scaleAsLines());
        lines.add("```");
        lines.add("");
        lines.add("This is a measure of size only -- how much would actually change -- and nothing else. "
                + "It does not decide whether the bot may carry the work out unattended; that is a separate "
                + "question, below.");
        lines.add("");
        lines.add("Score it honestly. This is not a request for permission, and there is no benefit in "
                + "scoring low to get the work done or high to avoid it -- a wrong score misrepresents how "
                + "invasive the change actually is.");
        lines.add("");
    }

    private static void appendAutomationSafety(List<String> lines) {
        lines.add("## Decide, per remediation group, whether it is safe to trust to automation");
        lines.add("");
        lines.add("This is a different question from the size score above, and you must answer it "
                + "separately, for every group. Set each group's `automationSafety` to exactly one of:");
        lines.add("");
        lines.add("- `AUTOMATIC_ALLOWED` -- the bot should carry out this group's plan, run every gate, and "
                + "commit the result locally on its own.");
        lines.add("- `HUMAN_REVIEW_REQUIRED` -- no automatic implementation should be attempted for this "
                + "group, whether because you found a safe, reviewable plan you are simply not authorising "
                + "to run unattended, or because you could not establish a safe plan at all, or because a "
                + "decision is needed that is not yours or the bot's to make unattended. Instead, a "
                + "separate, read-only Human Review Engineer will write up a report -- what is vulnerable, "
                + "why, and what you already established here -- for a person to act on. Nothing about "
                + "this group is changed by the bot.");
        lines.add("");
        lines.add("**Do not derive this from the size score.** A one-line version bump inside a "
                + "coordinated, runtime-sensitive dependency family -- for example a client library and its "
                + "transport, where the target versions have a proven binary-compatibility change and the "
                + "integration is exercised at runtime, not just at compile time -- can genuinely be "
                + "`impactScore: 3` and `HUMAN_REVIEW_REQUIRED` at the same time: the Maven diff is small, "
                + "but trusting it unreviewed is not warranted by that alone. Equally, a large, "
                + "multi-file change can be `AUTOMATIC_ALLOWED` at a high impact score if you found a clean, "
                + "well-understood path through it with a reliable way to validate the result. Judge the two "
                + "independently, on their own engineering merits.");
        lines.add("");
        lines.add("Explain your reasoning in `automationSafetyReason`, whichever value you chose.");
        lines.add("");
    }

    /**
     * Strengthens how human-review timing gets described. The bot may create an isolated local
     * remediation commit on its own, run its own build/Jenkins gates against it, and only then hand a
     * {@code HUMAN_REVIEW_REQUIRED} group to a person -- automatic merge is disabled regardless, always
     * (production defect, pilot {@code 20260909-061155-6ca4db}: analysis prose said a person "should
     * confirm ... before this is committed," which reads as already satisfied the moment the bot's own
     * local commit exists, when the actual, still-outstanding requirement is a check before the change
     * reaches its target branch or release).
     */
    private static void appendLifecycleWording(List<String> lines) {
        lines.add("## Describe human-review timing by lifecycle stage, never \"before commit\"");
        lines.add("");
        lines.add("The bot may create an isolated local remediation commit on its own, before a person "
                + "ever reviews this group -- that local commit is never itself a merge, a release, or a "
                + "publication, and automatic merge stays disabled regardless of anything you conclude "
                + "here. So when you describe what a person still needs to do, name the lifecycle stage it "
                + "actually blocks -- \"before merge\", \"before release\", \"before publication\", or "
                + "\"before runtime deployment\", whichever is genuinely true -- never \"before commit\" or "
                + "\"before this is committed\". Phrasing it as \"before commit\" reads as already "
                + "satisfied the moment the bot's own local commit exists, even though the real requirement "
                + "-- a human check before the change reaches its target branch, a release, or production -- "
                + "is still outstanding.");
        lines.add("");
    }

    private static void appendGrouping(List<String> lines) {
        lines.add("## Decide which findings must be remediated together");
        lines.add("");
        lines.add("Every finding whose `conclusion` is `REMEDIATION_REQUIRED` must belong to exactly one "
                + "remediation group, referenced by its `remediationGroupId`. A group may have one member "
                + "or several -- decide this purely from what your investigation actually established about "
                + "how the findings depend on and affect each other technically: a client and its transport "
                + "library that have to move together, several artifacts pinned by the same BOM, a fix that "
                + "is only half the picture without a sibling dependency that may not even have a finding of "
                + "its own. If a dependency with no finding of its own must move alongside a group, name it "
                + "in that group's `companionCoordinates`.");
        lines.add("");
        lines.add("A group's `sourceRef`, plan, size and automation-safety decision all describe the group "
                + "as a whole -- if the group has more than one member, that is one coordinated remediation "
                + "covering all of them, implemented and committed together, not several separate decisions.");
        lines.add("");
    }

    private static void appendNoActionRequiredStandard(List<String> lines) {
        lines.add("## What a NO_ACTION_REQUIRED conclusion requires");
        lines.add("");
        lines.add("A well-evidenced \"no action required\" is a real, valuable result -- but only when it "
                + "is actually settled, not merely the more literal or more repeated reading of one source. "
                + "Set `noActionBasis` to exactly one of these, whichever your investigation genuinely "
                + "established:");
        lines.add("");
        lines.add("- `DEPENDENCY_NOT_PRESENT` -- the coordinate is not present anywhere you examined.");
        lines.add("- `NO_FIXED_VERSION_EXISTS` -- the dependency is present, and no released version fixes "
                + "the vulnerability at all.");
        lines.add("- `ALREADY_AT_OR_ABOVE_FIXED_VERSION` -- a fixed version exists, and the version "
                + "genuinely in effect here already meets or exceeds it.");
        lines.add("");
        lines.add("**\"The vulnerable code path looks unreachable from this repository's own code\" is not, "
                + "by itself, grounds for NO_ACTION_REQUIRED** when a safe released fix exists -- "
                + "reachability is not one of the three bases above, because it does not remove the "
                + "dependency's own exposure the next time that code path does become reachable. If a fixed "
                + "version exists and applying it is safe, recommend the upgrade (`REMEDIATION_REQUIRED`) "
                + "even when you believe the path is not currently exercised; unreachability only "
                + "strengthens `NO_FIXED_VERSION_EXISTS` as a reason nothing more urgent is needed, it never "
                + "substitutes for it.");
        lines.add("");
        lines.add("**When your own sources disagree about which versions are actually affected** -- for "
                + "example, one piece of text names a version as still vulnerable \"through\" a certain "
                + "release, while another source (the project's own release notes, its fixed-commit or tag "
                + "history, the CVE/NVD entry, or the artifact's own code) shows that release already "
                + "contains the fix -- do not accept either wording at face value merely because it is the "
                + "more literal or more prominently repeated one. Resolve the contradiction against the most "
                + "authoritative source you can actually reach, and say in `evidence` what you checked and "
                + "what it showed. If, after genuinely trying, you still cannot resolve it, do not answer "
                + "`NO_ACTION_REQUIRED` at all: answer `REMEDIATION_REQUIRED` when a plausible fix exists and "
                + "you cannot rule out that it is still needed -- upgrading is the conservative default when "
                + "you cannot confidently clear the dependency -- or `INCONCLUSIVE` when even that judgment "
                + "cannot honestly be made, and use `risks` to say plainly what conflicted and what you could "
                + "not settle.");
        lines.add("");
    }

    private static void appendVersionRangeWording(List<String> lines) {
        lines.add("## Write affected-version and fixed-version ranges unambiguously");
        lines.add("");
        lines.add("When you state which versions are affected and which version is the fix, use explicit, "
                + "non-overlapping boundaries -- never a bare \"A-B\" shorthand when B is actually the fixed "
                + "version, since that reads as claiming B is both affected and fixed at the same time. "
                + "Prefer explicit inequality wording, for example \">= 2.22.0 and < 2.22.2\", or "
                + "\"affected before 2.22.2\" / \"fixed in 2.22.2 and later\" (these are illustrative "
                + "phrasing patterns only, not a real finding).");
        lines.add("");
        lines.add("If an upstream advisory's own wording is itself ambiguous or internally contradictory "
                + "-- for example, phrasing that could be read as naming the very same version both "
                + "affected and fixed -- say so explicitly and name the strongest evidence you actually "
                + "have, rather than repeating the ambiguous phrasing back as if it were a clean, "
                + "unambiguous fact.");
        lines.add("");
    }

    private static void appendPlannedChanges(List<String> lines) {
        lines.add("## Give each remediation group a machine-readable plan, not just a narrative one");
        lines.add("");
        lines.add("`implementationPlan` and `validationPlan` are for a person to read. `plannedChanges` is "
                + "the same plan again, but broken into the concrete, individually-verifiable edits the "
                + "Remediation Engineer must make -- the part a later automated check can objectively "
                + "confirm actually happened, without re-deriving your reasoning.");
        lines.add("");
        lines.add("**Every single entry, with no exceptions, needs all of these fields:**");
        lines.add("");
        lines.add("- `dependencyCoordinates` -- which coordinate this specific edit is about.");
        lines.add("- `affectedFile` -- which exact file it must land in; without this, nothing downstream "
                + "could ever verify it.");
        lines.add("- `currentVersion`/`targetVersion` -- where a version is actually involved (a plain "
                + "exclusion has neither; everything else naming a real version bump or pin needs both).");
        lines.add("- **`changeType` -- never omit this field, for any entry, for any reason.** If you "
                + "cannot confidently choose a more specific value, use `OTHER` and give a concrete `reason` "
                + "(see below) -- `OTHER` with a real reason is always valid and always machine-readable; a "
                + "missing `changeType` is not machine-readable at all and makes the entire batch "
                + "unparseable, discarding every finding's real conclusion along with it.");
        lines.add("- `reason` -- why this specific edit, in your own words.");
        lines.add("");
        lines.add("Set each entry's `changeType` to exactly one of these four values -- there is no fifth "
                + "option and no way to leave it blank:");
        lines.add("");
        lines.add("- `VERSION_BUMP` -- an existing dependency, property, or BOM control point changes "
                + "version (a literal tag, a property, a BOM-inherited value).");
        lines.add("- `DEPENDENCY_MANAGEMENT_ADDITION` -- a new `<dependencyManagement>` entry (or imported "
                + "BOM pin) is being added, or an existing one's coordinates/scope change (not just its "
                + "version -- a pure version change to an existing entry is `VERSION_BUMP`).");
        lines.add("- `EXCLUSION_ADDED` -- a Maven `<exclusion>` is being added.");
        lines.add("- `OTHER` -- the edit is not one of the three machine-verifiable kinds above. Deliberately "
                + "the weakest option: prefer a more specific value whenever one genuinely fits, and always "
                + "give a concrete, specific `reason` -- a group whose plan is entirely `OTHER` will be "
                + "treated as needing a person to look at it even if you set `AUTOMATIC_ALLOWED`, but that is "
                + "still far better than an unparseable document with no `changeType` at all.");
        lines.add("");
        lines.add("A `REMEDIATION_REQUIRED` group's `plannedChanges` should cover the same ground its "
                + "narrative `implementationPlan` describes -- do not leave it empty when you have a real "
                + "plan; a group with a narrative plan but no machine-readable one cannot be routed "
                + "automatically at all, however you set `automationSafety`.");
        lines.add("");
        lines.add("**Each `plannedChanges` entry must describe an actual repository/Maven edit the "
                + "Remediation Engineer is to make -- not every artifact whose resolved version happens to "
                + "change as a result.** A resolved dependency version change is not automatically a "
                + "planned repository change: if a vulnerable artifact has no Maven declaration or control "
                + "point of its own -- its version instead comes from an imported BOM, a parent's property, "
                + "a `dependencyManagement` entry, or a shared version property -- the entry belongs to "
                + "that actual control point, never to the vulnerable artifact's own coordinates as a "
                + "second, separate `VERSION_BUMP`.");
        lines.add("");
        lines.add("For example (illustrative only, not a real finding): the vulnerable artifact is "
                + "`com.example:library-a`, but the repository controls its version through an imported "
                + "`com.example:platform-bom` keyed off the property `${platform.version}`, and the actual "
                + "edit is `platform.version` `1.0` -> `1.1`. The correct `plannedChanges` is a single "
                + "`VERSION_BUMP` entry for `com.example:platform-bom` -- adding a second `VERSION_BUMP` "
                + "entry for `com.example:library-a` itself would be wrong, because `library-a` has no "
                + "separate declaration or control point for the Remediation Engineer to edit, and a later "
                + "structural check verifying the diff against your plan would find nothing there to "
                + "confirm.");
        lines.add("");
    }

    private static void appendExpectedOutput(List<String> lines) {
        lines.add("## What to return");
        lines.add("");
        lines.add("Write your analysis however is clearest -- the reasoning is read by people, and it is "
                + "kept. Then end your answer with a single fenced `json` block containing exactly this "
                + "document, and nothing after it:");
        lines.add("");
        lines.add("```json");
        lines.add(OUTPUT_SCHEMA);
        lines.add("```");
        lines.add("");
        lines.add("Anything you could not establish: omit the field, or set it to `null` or an empty list. "
                + "Do not fill a field in to look complete -- an absent value is read as \"not "
                + "established\", and inventing one is worse than leaving it out.");
        lines.add("");
        lines.add("Every finding needs `coordinates`, `summary` and `conclusion`. A `REMEDIATION_REQUIRED` "
                + "finding also needs `remediationGroupId`, naming a group below that carries its plan. A "
                + "`NO_ACTION_REQUIRED` finding must carry `evidence`, so the absence you are reporting is "
                + "supported, and must also carry `noActionBasis` (see above) -- and must not name a group. "
                + "An `INCONCLUSIVE` finding must carry `risks` or `evidence`, so it states what could not be "
                + "established, and must not name a group or a `noActionBasis` either.");
        lines.add("");
        lines.add("Every remediation group needs `groupId`, `memberCoordinates` naming every finding that "
                + "points at it, `impactScore`, `impactReason`, `automationSafety`, `automationSafetyReason`, "
                + "`recommendedRemediation`, `implementationPlan`, `validationPlan` and `plannedChanges` -- "
                + "without those there is nothing for anyone, or anything, to act on. Do not include a group "
                + "that no finding actually names.");
    }

    private String text(String value) {
        return findingRenderer.text(value);
    }
}
