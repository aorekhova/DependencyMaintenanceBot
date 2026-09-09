package com.tungsten.depbot.humanreview;

import com.tungsten.depbot.assessment.Assessments;
import com.tungsten.depbot.assessment.FindingAssessment;
import com.tungsten.depbot.report.SecretRedactor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HumanReviewFinalizationPromptRendererTest {

    private static final Path WORKSPACE = Path.of("C:", "repos", "WebApplication");

    private final HumanReviewFinalizationPromptRenderer renderer = new HumanReviewFinalizationPromptRenderer();

    private static HumanReviewContext groupContext() {
        FindingAssessment finding = Assessments.remediationRequiredFinding("g-bcprov");
        return new HumanReviewContext(
                "run1", "unit1", WORKSPACE, null, null,
                List.of(Assessments.workItem()), List.of(finding),
                Assessments.remediationGroup("g-bcprov", 2), "needs a human",
                List.of("com.example:companion"), null, null, null);
    }

    private static HumanReviewContext failedAnalysisContext() {
        return new HumanReviewContext(
                "run1", "unit1", WORKSPACE, null, null,
                List.of(Assessments.workItem()), List.of(), null, "analysis failed", List.of(),
                "The batch analysis did not produce a usable result: it ran out of turns.", null, null);
    }

    @Test
    @DisplayName("the prompt opens with its own marker, distinct from either phase's own marker")
    void promptOpensWithItsOwnMarker() {
        String prompt = renderer.render(groupContext(), true);

        assertTrue(prompt.startsWith(HumanReviewFinalizationPromptRenderer.FINALIZATION_MARKER), prompt);
    }

    @Test
    @DisplayName("a resumed session is told its own investigation is still available, and nothing is restated")
    void resumedSessionIsNotGivenARestatement() {
        String prompt = renderer.render(groupContext(), true);

        assertTrue(prompt.contains("Everything you had already established is still available"), prompt);
        assertFalse(prompt.contains("Why these findings belong together"), prompt);
        assertFalse(prompt.contains("Remediation recommended"), prompt);
    }

    @Test
    @DisplayName("a fresh call restates the group plan the earlier analysis already worked out")
    void freshCallRestatesTheGroupPlan() {
        String prompt = renderer.render(groupContext(), false);

        assertTrue(prompt.contains("could not be resumed"), prompt);
        assertTrue(prompt.contains("Why these findings belong together"), prompt);
        assertTrue(prompt.contains("raise the version property"), prompt);
        assertTrue(prompt.contains("Target version recommended"), prompt);
        assertTrue(prompt.contains("1.85"), prompt);
        assertTrue(prompt.contains("run dependency:tree"), prompt);
    }

    @Test
    @DisplayName("a fresh call restates the per-finding conclusion: evidence and risks the analysis already found")
    void freshCallRestatesTheFindingConclusion() {
        String prompt = renderer.render(groupContext(), false);

        assertTrue(prompt.contains("REMEDIATION_REQUIRED"), prompt);
        assertTrue(prompt.contains("git show origin/release/9.2:pom.xml shows 1.84"), prompt);
        assertTrue(prompt.contains("licence metadata"), prompt);
    }

    @Test
    @DisplayName("a fresh call restates companion coordinates the analysis named alongside the group")
    void freshCallRestatesCompanionCoordinates() {
        String prompt = renderer.render(groupContext(), false);

        assertTrue(prompt.contains("com.example:companion"), prompt);
    }

    @Test
    @DisplayName("a fresh call for a totally failed analysis restates whatever survived that failure")
    void freshCallRestatesPriorAnalysisFailureContext() {
        String prompt = renderer.render(failedAnalysisContext(), false);

        assertTrue(prompt.contains("did not produce a usable result"), prompt);
        assertTrue(prompt.contains("ran out of turns"), prompt);
    }

    @Test
    @DisplayName("a known credential appearing in Mend text never reaches the fresh-call prompt")
    void knownCredentialsAreMaskedOutOfThePrompt() {
        String credential = "mend-user-key-abcdef123456";
        HumanReviewContext context = new HumanReviewContext(
                "run1", "unit1", WORKSPACE, null, null,
                List.of(Assessments.workItem()), List.of(Assessments.remediationRequiredFinding()),
                Assessments.remediationGroup(2), "credential in reason: " + credential, List.of(), null,
                null, null);

        String prompt = new HumanReviewFinalizationPromptRenderer(SecretRedactor.of(credential))
                .render(context, false);

        assertFalse(prompt.contains(credential), "the credential reached the finalization prompt");
    }

    @Test
    @DisplayName("a null context is rejected rather than rendering a broken prompt")
    void nullContextIsRejected() {
        assertThrows(NullPointerException.class, () -> renderer.render(null, true));
    }
}
