package com.tungsten.depbot.humanreview;

import com.tungsten.depbot.assessment.Assessments;
import com.tungsten.depbot.assessment.FindingAssessment;
import com.tungsten.depbot.implementation.ImplementationConclusion;
import com.tungsten.depbot.remediation.DiagnosticClassification;
import com.tungsten.depbot.remediation.RejectedGroupOutcome;
import com.tungsten.depbot.remediation.RejectionStage;
import com.tungsten.depbot.validation.ValidationStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fast, no-Claude-needed regression tests for {@link HumanReviewPromptRenderer} -- in particular, the
 * evidence-priority fix from run {@code 20260919-221201-636b49}: a rejected group's own, later,
 * bot-verified "what the automatic attempt already established" evidence must be rendered before, and
 * framed as taking precedence over, Claude #1's original, pre-implementation plan -- so a stale open
 * question the original analysis raised is never repeated as if still unresolved once a later attempt
 * settled it, while a change that was established but rolled back is never described as if it were kept.
 */
class HumanReviewPromptRendererTest {

    private static final Path WORKSPACE = Path.of("C:", "repos", "WebApplication");

    private final HumanReviewPromptRenderer renderer = new HumanReviewPromptRenderer();

    /** A rejected-group dossier whose {@code whatChanged} resolves an open question the group's own
     *  {@code automationSafetyReason} (see {@link Assessments#remediationGroup(int)}) leaves stale. */
    private static RejectedGroupOutcome rejectedGroupOutcome() {
        return new RejectedGroupOutcome(
                null, "g-bcprov", "CRITICAL", 1, List.of("org.bouncycastle:bcprov-jdk18on"),
                "abc1234def5678", RejectionStage.PLAN_DEVIATION_REQUIRED,
                "raised the bouncycastle property and ran full validation",
                List.of("confirmed the companion module is not needed; the single dependency is sufficient"),
                ImplementationConclusion.COMPLETED, ValidationStatus.PASSED, ValidationStatus.PASSED,
                null, "plan conformance check failed: unauthorized file changed", true,
                "reverted to the accepted tip", true, List.of(), List.of(),
                DiagnosticClassification.DIAGNOSTIC_NOT_APPLICABLE, "--- a/pom.xml\n+++ b/pom.xml\n",
                null, List.of("unauthorized file changed: test-services/pom.xml"));
    }

    private static HumanReviewContext groupContextWithRejectedOutcome() {
        FindingAssessment finding = Assessments.remediationRequiredFinding("g-bcprov");
        return new HumanReviewContext(
                "run1", "unit1", WORKSPACE, null, null,
                List.of(Assessments.workItem()), List.of(finding),
                Assessments.remediationGroup("g-bcprov", 2), "an automatic attempt was rejected",
                List.of(), null, null, null, rejectedGroupOutcome());
    }

    @Test
    @DisplayName("what the automatic attempt already established is rendered before the original, "
            + "pre-implementation group plan")
    void rejectedGroupOutcomeIsRenderedBeforeGroupPlan() {
        String prompt = renderer.render(groupContextWithRejectedOutcome());

        int establishedIndex = prompt.indexOf("## What the automatic attempt already established");
        int groupPlanIndex = prompt.indexOf("## What the earlier analysis worked out for this group");

        assertTrue(establishedIndex >= 0, prompt);
        assertTrue(groupPlanIndex >= 0, prompt);
        assertTrue(establishedIndex < groupPlanIndex,
                "later, bot-verified evidence must be read before the original plan: " + prompt);
    }

    @Test
    @DisplayName("the original group plan section explicitly frames itself as pre-implementation context, "
            + "and instructs treating later evidence as authoritative when the two disagree")
    void groupPlanSectionContainsLaterEvidenceIsAuthoritativeFraming() {
        String prompt = renderer.render(groupContextWithRejectedOutcome());

        assertTrue(prompt.contains("ORIGINAL, pre-implementation assessment"), prompt);
        assertTrue(prompt.contains("treat that higher-precedence evidence as authoritative"), prompt);
        assertTrue(prompt.contains("never repeat a stale open question"), prompt);
        assertTrue(prompt.contains("never imply a fix was applied when it was rolled back"), prompt);
    }

    @Test
    @DisplayName("a later-established fact is shown alongside the honest fact that the change was not "
            + "retained -- never silently claiming success, never silently repeating the stale question")
    void rejectedOutcomeStillStatesChangeWasNotRetained() {
        String prompt = renderer.render(groupContextWithRejectedOutcome());

        assertTrue(prompt.contains("confirmed the companion module is not needed"), prompt);
        assertTrue(prompt.contains("plan conformance check failed"), prompt);
        assertTrue(prompt.contains("Rollback succeeded: true"), prompt);
    }

    // ---- Bug 3 (run 20260920-031107-148632): machine-owned evidence outranks the implementation's own
    // ---- "out of scope" narrative, and that precedence is stated explicitly ----------------------------

    /** A rejected-group dossier whose own narrative claims the vulnerable coordinate is out of scope, even
     *  though the machine-owned dependency-validation result says it still resolves. */
    private static RejectedGroupOutcome outOfScopeContradictedByValidatorOutcome() {
        return new RejectedGroupOutcome(
                null, "g-jsonlib", "CRITICAL", 1, List.of("net.sf.json-lib:json-lib"),
                "abc1234def5678", RejectionStage.DEPENDENCY_VALIDATION,
                "the report claimed net.sf.json-lib:json-lib was out of scope for this module",
                List.of("net.sf.json-lib:json-lib is out of scope: TestServices does not depend on it"),
                ImplementationConclusion.COMPLETED, ValidationStatus.FAILED, ValidationStatus.PASSED,
                null, "the dependency-resolution gate did not pass: TestServices -> jaxbjsonsdo:2.2 -> "
                        + "net.sf.json-lib:json-lib:2.4 remained on the resolved classpath", true,
                "reverted to the accepted tip", true, List.of(), List.of(),
                DiagnosticClassification.DIAGNOSTIC_NOT_APPLICABLE, null, null, List.of());
    }

    private static HumanReviewContext contextWithOutOfScopeContradiction() {
        FindingAssessment finding = Assessments.remediationRequiredFinding("g-jsonlib");
        return new HumanReviewContext(
                "run1", "unit1", WORKSPACE, null, null,
                List.of(Assessments.workItem()), List.of(finding),
                Assessments.remediationGroup("g-jsonlib", 2), "an automatic attempt was rejected",
                List.of(), null, null, null, outOfScopeContradictedByValidatorOutcome());
    }

    @Test
    @DisplayName("when the implementation's own narrative claims something is out of scope but the "
            + "machine-owned dependency-validation result disagrees, the prompt states the machine-owned "
            + "result is authoritative")
    void machineOwnedValidationOutranksAnOutOfScopeNarrative() {
        String prompt = renderer.render(contextWithOutOfScopeContradiction());

        assertTrue(prompt.contains("net.sf.json-lib:json-lib is out of scope"), prompt);
        assertTrue(prompt.contains("net.sf.json-lib:json-lib:2.4 remained on the resolved classpath"), prompt);
        assertTrue(prompt.contains("If the implementation's own narrative says something is out of scope, "
                + "already excluded, or otherwise resolved, but a machine-owned result in this same section "
                + "says otherwise"), prompt);
        assertTrue(prompt.contains("trust the machine-owned result"), prompt);

        int establishedIndex = prompt.indexOf("## What the automatic attempt already established");
        int outOfScopeIndex = prompt.indexOf("net.sf.json-lib:json-lib is out of scope");
        int precedenceIndex = prompt.indexOf("trust the machine-owned result");
        assertTrue(establishedIndex >= 0 && establishedIndex < outOfScopeIndex, prompt);
        assertTrue(precedenceIndex >= 0 && precedenceIndex < outOfScopeIndex,
                "the precedence rule must be stated before the contradicted narrative it governs: " + prompt);
    }

    // ---- regression: the other two input shapes still render without a section-ordering regression ----

    @Test
    @DisplayName("a single INCONCLUSIVE finding (no group, no rejected outcome) still renders cleanly")
    void inconclusiveFindingShapeStillRendersCleanly() {
        HumanReviewContext context = new HumanReviewContext(
                "run1", "unit1", WORKSPACE, null, null,
                List.of(Assessments.workItem()), List.of(Assessments.remediationRequiredFinding()),
                null, "inconclusive finding", List.of(), null, null, null);

        String prompt = renderer.render(context);

        assertTrue(prompt.contains("# Human review report"), prompt);
        assertTrue(prompt.contains("## What to return"), prompt);
    }

    @Test
    @DisplayName("a finding from a totally failed analysis (no group, no findingAssessments) still renders "
            + "cleanly")
    void failedAnalysisFindingShapeStillRendersCleanly() {
        HumanReviewContext context = new HumanReviewContext(
                "run1", "unit1", WORKSPACE, null, null,
                List.of(Assessments.workItem()), List.of(), null, "analysis failed", List.of(),
                "The batch analysis did not produce a usable result: it ran out of turns.", null, null);

        String prompt = renderer.render(context);

        assertTrue(prompt.contains("did not produce a usable result"), prompt);
        assertTrue(prompt.contains("## What to return"), prompt);
    }
}
