package com.tungsten.depbot.assessment;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fast, no-Claude-needed regression tests for {@link BatchAnalysisPromptRenderer} -- in particular, the
 * version-range wording guidance added for pilot {@code 20260909-012226-8bfda1}: an ambiguous "A-B"
 * affected-range shorthand, where B is actually the fix version, reads as claiming B is simultaneously
 * affected and fixed. This is purely a prompt-quality fix; nothing here names a real library or CVE, and
 * nothing in Java rewrites Claude's own prose -- see the renderer's own javadoc.
 */
class BatchAnalysisPromptRendererTest {

    @TempDir
    Path workspace;

    private String prompt() {
        return new BatchAnalysisPromptRenderer().render(Assessments.context(workspace));
    }

    @Test
    @DisplayName("the prompt instructs explicit, non-overlapping inclusive/exclusive version-range boundaries")
    void promptRequiresExplicitVersionBoundaries() {
        String prompt = prompt();

        assertTrue(prompt.contains("Write affected-version and fixed-version ranges unambiguously"), prompt);
        assertTrue(prompt.contains("explicit, "), prompt);
        assertTrue(prompt.contains(">= 2.22.0 and < 2.22.2") || prompt.contains("affected before"), prompt);
    }

    @Test
    @DisplayName("the prompt rules out bare \"A-B\" shorthand when B is actually the fixed version")
    void promptRulesOutAmbiguousShorthand() {
        String prompt = prompt();

        assertTrue(prompt.contains("\"A-B\" shorthand"), prompt);
        assertTrue(prompt.contains("claiming B is both affected and fixed"), prompt);
    }

    @Test
    @DisplayName("the prompt instructs flagging a contradictory or ambiguous upstream advisory explicitly, "
            + "rather than restating it as an unambiguous fact")
    void promptRequiresFlaggingAmbiguousAdvisoryWording() {
        String prompt = prompt();

        assertTrue(prompt.contains("ambiguous or internally contradictory"), prompt);
        assertTrue(prompt.contains("name the strongest evidence you actually have"), prompt);
    }

    @Test
    @DisplayName("the guidance is fully generic -- no CVE identifier appears in it, only the illustrative "
            + "version-number example")
    void guidanceNamesNoCve() {
        String prompt = prompt();
        int start = prompt.indexOf("Write affected-version and fixed-version ranges unambiguously");
        int end = prompt.indexOf("## ", start + 1);
        String section = end >= 0 ? prompt.substring(start, end) : prompt.substring(start);

        assertTrue(section.contains("2.22.0") || section.contains("2.22.2"),
                "the illustrative example itself must still be present: " + section);
        assertTrue(section.toLowerCase().indexOf("cve-") < 0,
                "no real CVE identifier may appear in this guidance: " + section);
    }

    // ---- Bug 4 (pilot 20260909-061155-6ca4db): lifecycle wording, never "before commit" ----------------

    @Test
    @DisplayName("the prompt instructs describing human-review timing by lifecycle stage -- merge, "
            + "release, publication or runtime deployment -- never as \"before commit\"")
    void promptRequiresLifecycleStageWordingNotBeforeCommit() {
        String prompt = prompt();

        assertTrue(prompt.contains("Describe human-review timing by lifecycle stage"), prompt);
        assertTrue(prompt.contains("\"before merge\""), prompt);
        assertTrue(prompt.contains("\"before release\""), prompt);
        assertTrue(prompt.contains("\"before publication\""), prompt);
        assertTrue(prompt.contains("\"before runtime deployment\""), prompt);
        assertTrue(prompt.contains("never \"before commit\""), prompt);
    }

    @Test
    @DisplayName("the prompt explains that an isolated local remediation commit may already exist before "
            + "human review, so \"before commit\" reads as already satisfied when it is not")
    void promptExplainsWhyBeforeCommitIsMisleading() {
        String prompt = prompt();

        assertTrue(prompt.contains("isolated local remediation commit on its own"), prompt);
        assertTrue(prompt.contains("automatic merge stays disabled regardless"), prompt);
        assertTrue(prompt.contains("reads as already satisfied the moment the bot's own local commit "
                + "exists"), prompt);
    }

    // ---- pilot 20260909-081921-1514ed: plannedChanges must name the real control point, not every -------
    // ---- coordinate whose resolved version happens to change ----------------------------------------------

    @Test
    @DisplayName("the prompt instructs that plannedChanges must describe an actual repository/Maven edit, "
            + "not every artifact whose resolved version changes as a side effect")
    void promptRequiresPlannedChangesToNameTheActualControlPoint() {
        String prompt = prompt();

        assertTrue(prompt.contains("must describe an actual repository/Maven edit"), prompt);
        assertTrue(prompt.contains("not every artifact whose resolved version happens to change"), prompt);
        assertTrue(prompt.contains("A resolved dependency version change is not automatically a planned "
                + "repository change"), prompt);
    }

    @Test
    @DisplayName("the prompt explicitly names BOM/parent-property/dependencyManagement/shared-property "
            + "control points as where the plannedChanges entry belongs instead of the vulnerable artifact")
    void promptNamesControlPointAlternatives() {
        String prompt = prompt();

        assertTrue(prompt.contains("an imported BOM"), prompt);
        assertTrue(prompt.contains("a parent's property"), prompt);
        assertTrue(prompt.contains("a `dependencyManagement` entry"), prompt);
        assertTrue(prompt.contains("a shared version property"), prompt);
        assertTrue(prompt.contains("never to the vulnerable artifact's own coordinates as a second, "
                + "separate `VERSION_BUMP`"), prompt);
    }

    @Test
    @DisplayName("the prompt's illustrative example shows a single VERSION_BUMP on the real control point, "
            + "not a second one on the vulnerable artifact with no control point of its own -- and it names "
            + "no real production library")
    void promptExampleShowsOnlyOneVersionBumpOnTheRealControlPoint() {
        String prompt = prompt();

        assertTrue(prompt.contains("com.example:library-a"), prompt);
        assertTrue(prompt.contains("com.example:platform-bom"), prompt);
        assertTrue(prompt.contains("${platform.version}"), prompt);
        assertTrue(prompt.contains("adding a second `VERSION_BUMP` entry for `com.example:library-a` "
                + "itself would be wrong"), prompt);
        assertTrue(prompt.toLowerCase(java.util.Locale.ROOT).indexOf("jackson") < 0,
                "production coordinates must never be hard-coded into this prompt: " + prompt);
    }
}
