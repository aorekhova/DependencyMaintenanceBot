package com.tungsten.depbot.implementation;

import com.tungsten.depbot.assessment.AnalysisRemediationGroup;
import com.tungsten.depbot.assessment.Assessments;
import com.tungsten.depbot.assessment.VulnerabilityWorkItem;
import com.tungsten.depbot.claude.ClaudePhase;
import com.tungsten.depbot.report.SecretRedactor;
import com.tungsten.depbot.report.actionable.AffectedLibrary;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ImplementationPromptRendererTest {

    private static final Path WORKSPACE = Path.of("C:", "repos", "WebApplication");
    private static final String BASE_SHA = "feedfacecafebabe1234567890abcdef12345678";

    private String prompt() {
        return new ImplementationPromptRenderer()
                .render(Implementations.context(WORKSPACE, BASE_SHA));
    }

    @Test
    @DisplayName("the prompt opens with the implementation phase marker")
    void promptOpensWithThePhaseMarker() {
        assertEquals(ClaudePhase.IMPLEMENTATION.promptMarker(), prompt().lines().findFirst().orElseThrow());
    }

    // ---- role and framing ------------------------------------------------------------------------

    @Test
    @DisplayName("the prompt states the role and that the judgment is the developer's")
    void promptStatesTheRole() {
        String prompt = prompt();

        assertTrue(prompt.contains("senior Java developer implementing this security remediation"), prompt);
        assertTrue(prompt.contains("if your own reading of the branch calls for something different, do the "
                + "right thing"), prompt);
    }

    @Test
    @DisplayName("the assessment is framed as a colleague's reasoning, not as a script to execute")
    void assessmentIsFramedAsContextNotScript() {
        String prompt = prompt();

        assertTrue(prompt.contains("Weigh it; do not obey it"), prompt);
        assertTrue(prompt.contains("not a script you are being measured against"), prompt);
        assertTrue(prompt.contains("assessment was written from a different checkout"), prompt);
    }

    @Test
    @DisplayName("the assessment is framed as already-completed investigation, not a starting point to redo")
    void assessmentIsFramedAsAlreadyCompletedInvestigation() {
        String prompt = prompt();

        assertTrue(prompt.contains("The assessment below is already the product of investigation"), prompt);
        assertTrue(prompt.contains("not a starting point to independently re-derive"), prompt);
        assertTrue(prompt.contains("not to redo the analysis that already produced it"), prompt);
    }

    @Test
    @DisplayName("checking the actual state is scoped to the minimal facts the plan depends on, not a redo")
    void checkingActualStateIsScopedToMinimalFacts() {
        String prompt = prompt();

        assertTrue(prompt.contains("check only the minimal facts the plan depends on"), prompt);
        assertTrue(prompt.contains("not a fresh investigation of the whole problem"), prompt);
        assertTrue(prompt.contains("If nothing you find contradicts the assessment, move straight to making "
                + "the edit"), prompt);
    }

    @Test
    @DisplayName("the budget priority is edit, then targeted validation, then report -- not repeated analysis")
    void budgetPriorityIsEditValidationReport() {
        String prompt = prompt();

        assertTrue(prompt.contains("Your budget's priority is the edit, then the targeted validation it "
                + "needs, then your report"), prompt);
        assertTrue(prompt.contains("not a repeat of the assessment's own analysis"), prompt);
    }

    @Test
    @DisplayName("further investigation is gated on a concrete contradiction or blocker, not a routine first step")
    void furtherInvestigationIsGatedOnAConcreteProblem() {
        String prompt = prompt();

        assertTrue(prompt.contains("Go beyond the minimal check above only when editing or validating "
                + "actually turns up something concrete"), prompt);
        assertTrue(prompt.contains("a real contradiction with the assessment, or a specific blocker"), prompt);
        assertTrue(prompt.contains("not routine first-step re-analysis"), prompt);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "First open",
            "First search every",
            "in this order",
            "step 1",
            "then edit",
            "start by",
            "follow these steps",
    })
    @DisplayName("the prompt is not a checklist of commands or files")
    void promptIsNotAChecklist(String procedural) {
        assertFalse(prompt().toLowerCase(Locale.ROOT).contains(procedural.toLowerCase(Locale.ROOT)),
                "the prompt must not become a checklist: found \"" + procedural + "\"");
    }

    // ---- the branch it is standing on -------------------------------------------------------------

    @Test
    @DisplayName("the branch, its base commit, and where that commit came from are all stated")
    void branchAndItsProvenanceAreStated() {
        String prompt = prompt();

        assertTrue(prompt.contains(Implementations.BRANCH), prompt);
        assertTrue(prompt.contains(BASE_SHA), prompt);
        assertTrue(prompt.contains("refs/remotes/origin/release/9.2"), prompt);
        assertTrue(prompt.contains("resolution was done by this bot against the repository, not taken from "
                + "the assessment"), prompt);
    }

    // ---- the whole problem, again ----------------------------------------------------------------

    @Test
    @DisplayName("the implementation gets the full original finding, not a digest of it")
    void implementationGetsTheFullFinding() {
        String prompt = prompt();

        assertTrue(prompt.contains("CVE-2026-58062"), prompt);
        assertTrue(prompt.contains("CVE-2026-59650"), prompt);
        assertTrue(prompt.contains("a description of CVE-2026-58062"), prompt);
        assertTrue(prompt.contains("disable the affected feature"),
                "recognising a wrong assessment needs the same evidence the assessment had");
    }

    @Test
    @DisplayName("the group's own plan, and each finding's own conclusion, are reproduced in full")
    void assessmentIsReproducedInFull() {
        String prompt = prompt();
        AnalysisRemediationGroup group = Assessments.remediationGroup(2);
        var findingAssessment = Assessments.remediationRequiredFinding();

        assertTrue(prompt.contains(findingAssessment.summary()), prompt);
        assertTrue(prompt.contains(group.recommendedRemediation()), prompt);
        assertTrue(prompt.contains(group.dependencyRelationship()), prompt);
        assertTrue(prompt.contains(group.impactReason()), prompt);
        for (String step : group.implementationPlan()) {
            assertTrue(prompt.contains(step), "missing plan step: " + step);
        }
        for (String step : group.validationPlan()) {
            assertTrue(prompt.contains(step), "missing validation step: " + step);
        }
        for (String evidence : findingAssessment.evidence()) {
            assertTrue(prompt.contains(evidence), "missing evidence: " + evidence);
        }
        for (String risk : findingAssessment.risks()) {
            assertTrue(prompt.contains(risk), "missing risk: " + risk);
        }
    }

    @Test
    @DisplayName("a group field that was never established reads as not provided")
    void unestablishedGroupFieldsReadAsNotProvided() {
        AnalysisRemediationGroup sparse = Assessments.withImpactScore(Assessments.remediationGroup(2), null);

        String prompt = new ImplementationPromptRenderer()
                .render(Implementations.context(WORKSPACE, BASE_SHA, sparse));

        assertTrue(prompt.contains("Size they scored it at: Not provided"), prompt);
    }

    // ---- authority ------------------------------------------------------------------------------

    @Test
    @DisplayName("the prompt grants the breadth a real remediation needs, with no POM-only restriction")
    void authorityIsBroadEnoughForARealRemediation() {
        String prompt = prompt();

        assertTrue(prompt.contains("Change whatever this remediation genuinely requires"), prompt);
        assertTrue(prompt.contains("no POM-only or version-only restriction"), prompt);
        assertTrue(prompt.contains("no limit on how many files or modules you may touch"), prompt);
        for (String allowed : List.of("Build configuration", "dependencyManagement", "version property",
                "Java sources", "tests", "resources", "generated third-party or licence metadata",
                "compatibility code")) {
            assertTrue(prompt.contains(allowed), "the prompt does not mention " + allowed);
        }
    }

    @Test
    @DisplayName("the only scope boundary stated is relevance to the remediation")
    void theOnlyScopeBoundaryIsRelevance() {
        String prompt = prompt();

        assertTrue(prompt.contains("The one boundary on scope is relevance"), prompt);
        assertFalse(prompt.contains("Any refactor broader than"),
                "the old artificial scope rule must not have crept back in");
        assertFalse(prompt.contains("Renaming or moving any class"), prompt);
    }

    @Test
    @DisplayName("tests may change but may not be deleted, disabled or skipped")
    void testsMayChangeButNotBeRemoved() {
        String prompt = prompt();

        assertTrue(prompt.contains("Do not delete or disable existing tests"), prompt);
        assertTrue(prompt.contains("change it and say so in your report"), prompt);
    }

    @Test
    @DisplayName("the final commit-or-rollback decision is stated as the bot's, and publishing as never happening here")
    void finalDecisionBelongsToTheBotAndPublishingNeverHappens() {
        String prompt = prompt();

        assertTrue(prompt.contains("What is not yours is finishing the job with it"), prompt);
        assertTrue(prompt.contains("leave the remediation itself as ordinary, uncommitted working-tree "
                + "edits"), prompt);
        assertTrue(prompt.contains("must never push"), prompt);
        assertTrue(prompt.contains("Publishing anything at all"), prompt);
        assertTrue(prompt.contains("the bot still finds and reviews exactly the same change"), prompt);
    }

    @Test
    @DisplayName("git is stated as fully available locally, including commit, for Claude's own workflow")
    void gitIsStatedAsFullyAvailableLocally() {
        String prompt = prompt();

        assertTrue(prompt.contains("Git is yours to use freely for local investigation"), prompt);
        assertTrue(prompt.contains("git diff"), prompt);
        assertTrue(prompt.contains("git commit"), prompt);
    }

    @Test
    @DisplayName("a full developer environment -- shell, Maven, web search -- is described, not a command allow-list")
    void fullDeveloperEnvironmentIsDescribed() {
        String prompt = prompt();

        assertTrue(prompt.contains("full developer environment"), prompt);
        assertTrue(prompt.contains("unrestricted shell"), prompt);
        assertTrue(prompt.contains("web search"), prompt);
    }

    @Test
    @DisplayName("the prompt forbids opening or reproducing anything holding a secret")
    void promptForbidsTouchingSecrets() {
        String prompt = prompt();

        assertTrue(prompt.contains(".env.local"), prompt);
        assertTrue(prompt.contains("private keys"), prompt);
        assertTrue(prompt.contains("leave it closed"), prompt);
    }

    @Test
    @DisplayName("a known credential in Mend text never reaches the prompt")
    void credentialsAreMaskedOutOfThePrompt() {
        String credential = "mend-user-key-abcdef123456";
        AffectedLibrary library = new AffectedLibrary("g", "a", "1.0", "g:a:1.0", "a", "a.jar", "JAVA",
                null, null, null, null, "vendor note: " + credential);
        VulnerabilityWorkItem item = new VulnerabilityWorkItem("g", "a", "1.0", "HIGH", "2.0",
                List.of(Assessments.finding("CVE-X", "high", library, "token " + credential)));
        ImplementationContext context = new ImplementationContext("run1", "unit1", WORKSPACE,
                Implementations.BRANCH, BASE_SHA, "refs/remotes/origin/master", Assessments.remediationGroup(2),
                item, Assessments.remediationRequiredFinding());

        String prompt = new ImplementationPromptRenderer(SecretRedactor.of(credential)).render(context);

        assertFalse(prompt.contains(credential), "the credential reached prompt.md");
        assertTrue(prompt.contains(SecretRedactor.MASK), prompt);
    }

    // ---- the stop rule ---------------------------------------------------------------------------

    @Test
    @DisplayName("stopping on a contradicted premise is instructed, named, and called a good outcome")
    void stoppingOnContradictionIsInstructedAndNotPenalised() {
        String prompt = prompt();

        assertTrue(prompt.contains("Stop. Do not force the plan through."), prompt);
        assertTrue(prompt.contains(ImplementationConclusion.STOPPED_ASSESSMENT_CONTRADICTED.name()), prompt);
        assertTrue(prompt.contains("This is a good outcome, not a failure"), prompt);
        assertTrue(prompt.contains("you must not use git to do so"),
                "an agent told to stop must also be told the bot undoes its partial work, not it");
    }

    @Test
    @DisplayName("the prompt names the cases that count as a contradicted premise")
    void contradictionCasesAreNamed() {
        String prompt = prompt();

        assertTrue(prompt.contains("not present the way the assessment described"), prompt);
        assertTrue(prompt.contains("already at a fixed version"), prompt);
        assertTrue(prompt.contains("would be a downgrade or does not exist"), prompt);
    }

    @Test
    @DisplayName("a branch contradiction is tied back to the concrete-problem gate on further investigation")
    void contradictionIsTiedBackToTheConcreteProblemGate() {
        String prompt = prompt();

        assertTrue(prompt.contains("This is exactly the concrete contradiction that warrants going beyond "
                + "the targeted check above"), prompt);
    }

    @Test
    @DisplayName("a smaller disagreement is distinguished from a stop")
    void smallerDisagreementIsDistinguished() {
        String prompt = prompt();

        assertTrue(prompt.contains("A smaller disagreement is different"), prompt);
        assertTrue(prompt.contains("record the disagreement in `divergenceFromAssessment`"), prompt);
    }

    // ---- the contract it must return -------------------------------------------------------------

    @Test
    @DisplayName("the requested document names every field the report model binds")
    void requestedDocumentNamesEveryField() {
        String prompt = prompt();

        for (String field : List.of("schemaVersion", "coordinates", "conclusion", "summary",
                "observedState", "changesMade", "divergenceFromAssessment", "validationPerformed",
                "remainingWork", "risks")) {
            assertTrue(prompt.contains("\"" + field + "\""), "the schema omits " + field);
        }
    }

    @Test
    @DisplayName("every conclusion is offered, so stopping is a first-class answer")
    void everyConclusionIsOffered() {
        String prompt = prompt();

        for (ImplementationConclusion conclusion : ImplementationConclusion.values()) {
            assertTrue(prompt.contains(conclusion.name()), "the schema omits " + conclusion);
        }
    }

    @Test
    @DisplayName("the prompt says plainly that only a completed conclusion gets committed")
    void promptSaysWhatDecidesWhetherWorkIsKept() {
        String prompt = prompt();

        assertTrue(prompt.contains("commits the change only on a `COMPLETED` conclusion"), prompt);
        assertTrue(prompt.contains("only after checking the diff"), prompt);
        assertTrue(prompt.contains("Reporting completion you are not confident in does not get the change "
                + "accepted"), prompt);
    }

    @Test
    @DisplayName("the answer is asked for as one fenced json block, which is what the parser looks for")
    void answerIsAskedForAsOneFencedJsonBlock() {
        String prompt = prompt();

        assertTrue(prompt.contains("single fenced `json` block"), prompt);
        assertTrue(prompt.contains("nothing after it"), prompt);
    }

    @Test
    @DisplayName("the schema the prompt shows is a document the parser can find")
    void shownSchemaIsFindableByTheParser() {
        assertTrue(com.tungsten.depbot.claude.JsonAnswerExtractor.lastJsonObject(prompt())
                .contains("\"observedState\""));
    }

    // ---- multi-member remediation groups ------------------------------------------------------------

    private static VulnerabilityWorkItem otherItem() {
        return new VulnerabilityWorkItem("com.example", "other", "1.0", "CRITICAL", "2.0", List.of());
    }

    @Test
    @DisplayName("a multi-member group is told it covers several findings together, not framed as one")
    void multiMemberGroupIsFramedAsSeveralFindingsTogether() {
        AnalysisRemediationGroup group = Assessments.withMemberCoordinates(Assessments.remediationGroup(2),
                "org.bouncycastle:bcprov-jdk18on", "com.example:other");
        var findingAssessment = Assessments.remediationRequiredFinding();
        ImplementationContext context = new ImplementationContext("run1", "unit1", WORKSPACE,
                Implementations.BRANCH, BASE_SHA, "refs/remotes/origin/release/9.2", group,
                List.of(new ImplementationGroupMember(Assessments.workItem(), findingAssessment),
                        new ImplementationGroupMember(otherItem(), findingAssessment)),
                List.of());

        String prompt = new ImplementationPromptRenderer().render(context);

        assertTrue(prompt.contains("This call covers 2 findings, not one"), prompt);
        assertTrue(prompt.contains("Finding 1 of 2"), prompt);
        assertTrue(prompt.contains("Finding 2 of 2"), prompt);
        assertTrue(prompt.contains("org.bouncycastle:bcprov-jdk18on"), prompt);
        assertTrue(prompt.contains("com.example:other"), prompt);
    }

    @Test
    @DisplayName("a single-member group is framed exactly as an ordinary single finding, with no numbering")
    void singleMemberGroupHasNoFindingNumbering() {
        String prompt = prompt();

        assertFalse(prompt.contains("Finding 1 of 1"), prompt);
        assertTrue(prompt.contains("A colleague has already assessed the problem"), prompt);
    }

    @Test
    @DisplayName("companion coordinates with no Mend finding of their own are listed and explained")
    void companionCoordinatesAreListedAndExplained() {
        ImplementationContext context = new ImplementationContext("run1", "unit1", WORKSPACE,
                Implementations.BRANCH, BASE_SHA, "refs/remotes/origin/release/9.2",
                Assessments.remediationGroup(2),
                List.of(new ImplementationGroupMember(
                        Assessments.workItem(), Assessments.remediationRequiredFinding())),
                List.of("com.example:companion"));

        String prompt = new ImplementationPromptRenderer().render(context);

        assertTrue(prompt.contains("com.example:companion"), prompt);
        assertTrue(prompt.contains("no Mend finding of their own"), prompt);
    }

    @Test
    @DisplayName("with no companion coordinates, no companion section is rendered at all")
    void noCompanionSectionWhenThereAreNoCompanions() {
        assertFalse(prompt().contains("Related coordinates with no Mend finding"), prompt());
    }

    // ---- the remediation plan is a binding execution contract --------------------------------------

    @Test
    @DisplayName("the group's own plan is rendered as a binding execution contract, including its planned changes")
    void groupPlanIsRenderedAsABindingContract() {
        AnalysisRemediationGroup group = Assessments.remediationGroupWithPlannedChanges(2);
        String prompt = new ImplementationPromptRenderer()
                .render(Implementations.context(WORKSPACE, BASE_SHA, group));

        assertTrue(prompt.contains("## The remediation plan (binding execution contract)"), prompt);
        assertTrue(prompt.contains("This plan is a binding execution contract, not a suggestion"), prompt);
        assertTrue(prompt.contains("must not choose a different target version"), prompt);
        for (String step : group.implementationPlan()) {
            assertTrue(prompt.contains(step), "missing group plan step: " + step);
        }
        var change = group.plannedChanges().get(0);
        assertTrue(prompt.contains(change.dependencyCoordinates()), prompt);
        assertTrue(prompt.contains(change.currentVersion()), prompt);
        assertTrue(prompt.contains(change.targetVersion()), prompt);
        assertTrue(prompt.contains(change.affectedFile()), prompt);
        assertTrue(prompt.contains(change.changeType().name()), prompt);
    }

    @Test
    @DisplayName("the plan-deviation stop rule is always present, naming the conclusion and what it requires")
    void planDeviationStopRuleIsAlwaysPresent() {
        String prompt = prompt();

        assertTrue(prompt.contains("## If the approved plan itself is incomplete or wrong"), prompt);
        assertTrue(prompt.contains(ImplementationConclusion.STOPPED_PLAN_DEVIATION_REQUIRED.name()), prompt);
        assertTrue(prompt.contains("Do not improvise a fix"), prompt);
        assertTrue(prompt.contains("A `STOPPED_PLAN_DEVIATION_REQUIRED` conclusion must likewise carry "
                + "`risks` or `remainingWork`"), prompt);
    }

    // ---- a repair attempt gets the previous attempt's own evidence ----------------------------------

    @Test
    @DisplayName("with no repair context, no repair-attempt section is rendered")
    void noRepairSectionWithoutARepairContext() {
        assertFalse(prompt().contains("This is a repair attempt"), prompt());
    }

    @Test
    @DisplayName("a repair context renders the failed stage, the evidence, and an explicit "
            + "don't-re-investigate instruction")
    void repairContextIsRendered() {
        String prompt = new ImplementationPromptRenderer()
                .render(Implementations.contextWithRepairContext(WORKSPACE, BASE_SHA));
        var repair = Implementations.repairContext();

        assertTrue(prompt.contains("This is a repair attempt"), prompt);
        assertTrue(prompt.contains("do not re-investigate the finding from scratch"), prompt);
        assertTrue(prompt.contains(repair.failedStage().name()), prompt);
        assertTrue(prompt.contains(repair.exactErrorEvidenceSummary()), prompt);
        assertTrue(prompt.contains(repair.dependencyValidationOutcome().reason()), prompt);
    }

    // ---- Bug 3 (pilot 20260909-061155-6ca4db): the remainingWork contract is strengthened -----------

    @Test
    @DisplayName("the prompt states remainingWork is only for mandatory, unfinished, merge/release-blocking "
            + "human actions -- never optional or informational content")
    void remainingWorkContractIsExplicit() {
        String prompt = prompt();

        assertTrue(prompt.contains("What belongs in `remainingWork`"), prompt);
        assertTrue(prompt.contains("concrete action"), prompt);
        assertTrue(prompt.contains("genuinely unfinished"), prompt);
        assertTrue(prompt.contains("block merge/release"), prompt);
    }

    @Test
    @DisplayName("the prompt explicitly routes optional recommendations away from remainingWork")
    void optionalRecommendationsAreRoutedAwayFromRemainingWork() {
        String prompt = prompt();

        assertTrue(prompt.contains("optional recommendation"), prompt);
        assertTrue(prompt.contains("Never `remainingWork` merely because it is worth someone's attention"),
                prompt);
    }

    @Test
    @DisplayName("the prompt explicitly routes informational/explanatory notes away from remainingWork")
    void informationalNotesAreRoutedAwayFromRemainingWork() {
        String prompt = prompt();

        assertTrue(prompt.contains("An explanation of why you left something as an uncommitted "
                + "working-tree edit"), prompt);
        assertTrue(prompt.contains("never `remainingWork` -- that field is for what is still undone, "
                + "not for commentary on what you already did"), prompt);
    }

    @Test
    @DisplayName("the prompt states remainingWork must be empty when no mandatory unfinished human action "
            + "exists")
    void emptyRemainingWorkIsExplicitlyRequiredWhenNothingIsOutstanding() {
        String prompt = prompt();

        assertTrue(prompt.contains("`remainingWork` must be an empty list"), prompt);
        assertTrue(prompt.contains("a normal, good outcome"), prompt);
    }

    @Test
    @DisplayName("the prompt gives a generic good example and generic bad examples, naming no real "
            + "production library or CVE")
    void examplesAreGenericNotHardcodedToARealLibrary() {
        String prompt = prompt();

        assertTrue(prompt.contains("Run SAML SSO against the test IdP over HTTPS"), prompt);
        assertTrue(prompt.contains("Optional hardening: consider enabling X"), prompt);
        assertTrue(prompt.contains("Document why version Y is safe"), prompt);
        assertTrue(prompt.contains("This was intentionally left unchanged"), prompt);
        assertTrue(prompt.contains("Review if desired"), prompt);
        assertFalse(prompt.toLowerCase(Locale.ROOT).contains("struts"), prompt);
        assertFalse(prompt.toLowerCase(Locale.ROOT).contains("jsoup"), prompt);
        assertFalse(prompt.toLowerCase(Locale.ROOT).matches(".*cve-\\d.*"), prompt);
    }
}
