package com.tungsten.depbot.implementation;

import com.tungsten.depbot.report.SecretRedactor;
import com.tungsten.depbot.report.actionable.AffectedLibrary;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ImplementationFinalizationPromptRendererTest {

    private static final Path WORKSPACE = Path.of("C:", "repos", "WebApplication");
    // No leading space -- the renderer's blockOrNone(value) calls String.strip(), which trims only the
    // ends of the whole block, not each line, so a fixture with a leading space here would never
    // actually appear verbatim in the rendered prompt.
    private static final String STATUS = "M pom.xml\n?? notes.txt";
    private static final String DIFF_STAT = "pom.xml | 2 +-\n 1 file changed, 1 insertion(+), 1 deletion(-)";
    private static final String DIFF = "diff --git a/pom.xml b/pom.xml\n-<version>1.0</version>\n+<version>1.1</version>";

    private final ImplementationFinalizationPromptRenderer renderer =
            new ImplementationFinalizationPromptRenderer();

    private static ImplementationContext context() {
        return Implementations.context(WORKSPACE, "0123456789abcdef0123456789abcdef01234567");
    }

    private String render(boolean resuming) {
        return renderer.render(context(), resuming, STATUS, DIFF, DIFF_STAT);
    }

    @Test
    @DisplayName("the prompt opens with its own marker, distinct from either phase's own marker")
    void promptOpensWithItsOwnMarker() {
        String prompt = render(true);

        assertTrue(prompt.startsWith(ImplementationFinalizationPromptRenderer.FINALIZATION_MARKER), prompt);
        assertFalse(ImplementationFinalizationPromptRenderer.FINALIZATION_MARKER
                        .equals(com.tungsten.depbot.claude.ClaudePhase.IMPLEMENTATION.promptMarker()),
                "the finalization marker must never collide with the implementation phase's own marker");
    }

    @Test
    @DisplayName("the prompt states plainly that no further edits happen, whichever variant is rendered")
    void promptStatesNoFurtherEditsHappen() {
        assertTrue(render(true).contains("No further edits happen in this call"));
        assertTrue(render(false).contains("No further edits happen in this call"));
    }

    @Test
    @DisplayName("the prompt states plainly that this call has no tools at all -- the core of the fix")
    void promptStatesNoToolsAtAll() {
        assertTrue(render(true).contains("you have no tools at all in this call"));
        assertTrue(render(false).contains("you have no tools at all in this call"));
    }

    @Test
    @DisplayName("the prompt never instructs Claude to run git diff or git status itself")
    void promptNeverInstructsRunningGitItself() {
        for (boolean resuming : List.of(true, false)) {
            String prompt = render(resuming);
            assertFalse(prompt.contains("Use `git diff"), prompt);
            assertFalse(prompt.contains("you have read-only access"), prompt);
        }
    }

    @Test
    @DisplayName("the precomputed status, diff and diffstat all appear verbatim in the prompt")
    void precomputedEvidenceAppearsVerbatim() {
        String prompt = render(false);

        assertTrue(prompt.contains(STATUS), prompt);
        assertTrue(prompt.contains(DIFF_STAT), prompt);
        assertTrue(prompt.contains(DIFF), prompt);
    }

    @Test
    @DisplayName("blank evidence renders an explicit placeholder rather than an empty block")
    void blankEvidenceRendersPlaceholder() {
        String prompt = renderer.render(context(), false, "", "", "  ");

        assertTrue(prompt.contains("no output -- nothing to show"), prompt);
    }

    @Test
    @DisplayName("a resumed session is told to use what it already reasoned about")
    void resumedSessionIsToldToUseWhatItAlreadyKnows() {
        String prompt = render(true);

        assertTrue(prompt.contains("continues the session you were already implementing in"), prompt);
        assertFalse(prompt.contains("could not be resumed"), prompt);
    }

    @Test
    @DisplayName("a fresh call with no session is told the evidence below is everything it has")
    void freshCallIsToldTheEvidenceIsEverythingItHas() {
        String prompt = render(false);

        assertTrue(prompt.contains("could not be resumed"), prompt);
        assertTrue(prompt.contains(Implementations.BRANCH), prompt);
    }

    @Test
    @DisplayName("both variants guide the answer toward COMPLETED or STOPPED_BLOCKED specifically")
    void bothVariantsGuideTowardCompletedOrStoppedBlocked() {
        for (boolean resuming : List.of(true, false)) {
            String prompt = render(resuming);

            assertTrue(prompt.contains("say so: `conclusion` of `COMPLETED`"), prompt);
            assertTrue(prompt.contains("say that instead: `conclusion` of `STOPPED_BLOCKED`"), prompt);
        }
    }

    @Test
    @DisplayName("the prompt refuses to let an unconfident report overstate completion")
    void promptRefusesOverstatingCompletion() {
        String prompt = render(true);

        assertTrue(prompt.contains("Do not report `COMPLETED` just because a diff exists above"), prompt);
    }

    @Test
    @DisplayName("the same output schema the original implementation call used is asked for again")
    void sameOutputSchemaIsRequested() {
        String prompt = render(true);

        for (String field : List.of("schemaVersion", "coordinates", "conclusion", "observedState",
                "changesMade", "remainingWork", "risks")) {
            assertTrue(prompt.contains("\"" + field + "\""), "the schema omits " + field);
        }
    }

    @Test
    @DisplayName("a known credential appearing in Mend text never reaches the fresh-call prompt")
    void knownCredentialsAreMaskedOutOfThePrompt() {
        String credential = "mend-user-key-abcdef123456";
        AffectedLibrary library = new AffectedLibrary("g", "a", "1.0", "g:a:1.0", "a", "a.jar", "JAVA",
                null, null, null, null, "vendor said: " + credential);
        var item = new com.tungsten.depbot.assessment.VulnerabilityWorkItem("g", "a", "1.0", "HIGH", "2.0",
                List.of(com.tungsten.depbot.assessment.Assessments.finding("CVE-X", "high", library,
                        "token " + credential)));
        ImplementationContext context = new ImplementationContext("run1", "unit1", WORKSPACE,
                Implementations.BRANCH, "sha", "refs/remotes/origin/master",
                com.tungsten.depbot.assessment.Assessments.remediationGroup(2), item,
                com.tungsten.depbot.assessment.Assessments.remediationRequiredFinding());

        String prompt = new ImplementationFinalizationPromptRenderer(SecretRedactor.of(credential))
                .render(context, false, "", "", "");

        assertFalse(prompt.contains(credential), "the credential reached the finalization prompt");
    }

    @Test
    @DisplayName("a credential appearing in the precomputed diff evidence itself is also masked")
    void credentialsInPrecomputedEvidenceAreMasked() {
        String credential = "mend-user-key-abcdef123456";
        String prompt = new ImplementationFinalizationPromptRenderer(SecretRedactor.of(credential))
                .render(context(), false, "", "+token " + credential, "");

        assertFalse(prompt.contains(credential), "the credential reached the finalization prompt");
    }

    @Test
    @DisplayName("a null context is rejected rather than rendering a broken prompt")
    void nullContextIsRejected() {
        assertThrows(NullPointerException.class, () -> renderer.render(null, true, "", "", ""));
    }
}
