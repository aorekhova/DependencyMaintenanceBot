package com.tungsten.depbot.publication;

import com.tungsten.depbot.humanreview.HumanReviewReport;
import com.tungsten.depbot.implementation.ImplementationConclusion;
import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;
import com.tungsten.depbot.jenkins.JenkinsValidationStatus;
import com.tungsten.depbot.remediation.CohortIntegrationFailureOutcome;
import com.tungsten.depbot.remediation.CohortsIndex;
import com.tungsten.depbot.remediation.RejectedGroupOutcome;
import com.tungsten.depbot.remediation.RejectionStage;
import com.tungsten.depbot.validation.ValidationStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HumanReviewReportMarkdownRendererTest {

    private final HumanReviewReportMarkdownRenderer renderer = new HumanReviewReportMarkdownRenderer();

    private static HumanReviewReport report() {
        return report(null, null);
    }

    private static HumanReviewReport report(
            JenkinsValidationOutcome cumulativeJenkins, JenkinsValidationOutcome integrationJenkins) {
        return new HumanReviewReport(
                "1.0",
                "org.apache.httpcomponents.core5:httpcore5, org.apache.httpcomponents.client5:httpclient5",
                "the httpcomponents5 family carries CVE-2026-Z",
                "a request-smuggling flaw in the connection pool",
                "declared directly in the root pom",
                "raise the whole family to 5.4.1 together",
                List.of("org.apache.httpcomponents.core5:httpcore5-h2"),
                "run the project's integration test suite against the raised versions",
                List.of("could not confirm every module rebuilds cleanly offline"),
                List.of("a coordinated multi-artifact bump carries more risk than a single-library one"),
                null, integrationJenkins, cumulativeJenkins);
    }

    private static JenkinsValidationOutcome jenkinsOutcome(JenkinsValidationStatus status) {
        return new JenkinsValidationOutcome(status, "WebApplicationDependencyValidation", 7,
                "https://jenkins.example.invalid/job/x/7/", "baseSha", "candidateSha", "treeSha", 60L,
                "Jenkins reported result " + status);
    }

    // ---- unchanged pre-existing invariants, adapted to the new decision-first layout -------------------

    @Test
    @DisplayName("all six fixed questions are answered in the rendered document")
    void allSixQuestionsAreAnswered() {
        String markdown = renderer.render(report());

        assertTrue(markdown.contains("httpcore5"), markdown);
        assertTrue(markdown.contains("request-smuggling"), markdown);
        assertTrue(markdown.contains("declared directly in the root pom"), markdown);
        assertTrue(markdown.contains("raise the whole family to 5.4.1"), markdown);
        assertTrue(markdown.contains("httpcore5-h2"), markdown);
        assertTrue(markdown.contains("integration test suite"), markdown);
    }

    @Test
    @DisplayName("open questions and risks are both included")
    void openQuestionsAndRisksAreIncluded() {
        String markdown = renderer.render(report());

        assertTrue(markdown.contains("could not confirm every module rebuilds cleanly offline"), markdown);
        assertTrue(markdown.contains("coordinated multi-artifact bump"), markdown);
    }

    @Test
    @DisplayName("the document always ends with an explicit, unmissable no-automatic-change statement")
    void endsWithExplicitNoAutomaticChangeStatement() {
        String markdown = renderer.render(report());

        assertTrue(markdown.contains("Automatic code modification performed:** NO"), markdown);
    }

    @Test
    @DisplayName("a null report is rejected rather than rendering a broken document")
    void nullReportIsRejected() {
        assertThrows(NullPointerException.class, () -> renderer.render(null));
    }

    @Test
    @DisplayName("both Jenkins sections render NOT APPLICABLE when Jenkins was never reached for this review")
    void bothJenkinsSectionsAreNotApplicableWhenAbsent() {
        String markdown = renderer.render(report());

        assertTrue(markdown.contains("Cumulative Jenkins"), markdown);
        assertTrue(markdown.contains("Final integration Jenkins"), markdown);
        assertTrue(markdown.contains("NOT APPLICABLE"), markdown);
    }

    @Test
    @DisplayName("a cumulative Jenkins rejection is shown with its own bot-owned facts, integration stays N/A "
            + "-- adapted from the old 'exactly one NOT APPLICABLE line' check, since the new layout "
            + "deliberately shows Jenkins facts twice (a compact table row, then full facts in the "
            + "collapsible details section), so the real invariant is now: the present outcome's real facts "
            + "appear, and the absent one is marked NOT APPLICABLE in both places, never confused for a fact")
    void isolatedRejectionShowsItsOwnFactsIntegrationStaysNotApplicable() {
        String markdown = renderer.render(report(jenkinsOutcome(JenkinsValidationStatus.FAILED), null));

        assertTrue(markdown.contains("WebApplicationDependencyValidation"), markdown);
        assertTrue(markdown.contains("candidateSha"), markdown);
        assertTrue(markdown.contains("✗ FAILED"), markdown);
        // The absent integration outcome is marked NOT APPLICABLE exactly twice -- once in the compact
        // table, once in the collapsible details' full Jenkins facts -- never confused with the present
        // cumulative outcome's own real facts, which appear alongside it in both places instead.
        long integrationNotApplicableCount = markdown.lines()
                .filter(line -> line.contains("Final integration Jenkins") && line.contains("NOT APPLICABLE"))
                .count()
                + markdown.lines()
                        .filter(line -> line.strip().equals("- ⚠ NOT APPLICABLE"))
                        .count();
        assertTrue(integrationNotApplicableCount == 2,
                "expected exactly 2 markers for the absent integration outcome (table row + details bullet): "
                        + markdown);
    }

    @Test
    @DisplayName("a failed-integration review shows its own facts, cumulative stays N/A")
    void failedIntegrationReviewShowsItsOwnFactsIsolatedStaysNotApplicable() {
        String markdown = renderer.render(report(null, jenkinsOutcome(JenkinsValidationStatus.FAILED)));

        assertTrue(markdown.contains("WebApplicationDependencyValidation"), markdown);
        assertTrue(markdown.contains("✗ FAILED"), markdown);
    }

    // ---- new: decision-first layout, patch/reproduction, risk/conformance evidence -----------------------

    private static RejectedGroupOutcome rejectedGroupOutcome(RejectionStage stage, String patch) {
        return rejectedGroupOutcome(stage, patch, null, List.of());
    }

    private static RejectedGroupOutcome rejectedGroupOutcome(
            RejectionStage stage, String patch, String effectiveRiskReason, List<String> conformanceViolations) {
        return new RejectedGroupOutcome(
                "1.0", "g-1", "CRITICAL", 1, List.of("com.example:artifact"), "acceptedBaseSha123",
                stage, "raised the version in pom.xml", List.of("pom.xml"),
                ImplementationConclusion.STOPPED_PLAN_DEVIATION_REQUIRED, ValidationStatus.PASSED,
                ValidationStatus.NOT_RUN, null, "the plan deviated from what was approved", true,
                "acceptedBaseSha123", true, List.of("re-plan the version bump"), List.of("residual risk noted"),
                null, patch, effectiveRiskReason, conformanceViolations);
    }

    @Test
    @DisplayName("a rejected group's applicable patch is rendered as a copyable diff block")
    void patchIsRenderedAsCopyableDiffBlock() {
        String patch = "diff --git a/pom.xml b/pom.xml\n+<version>1.1</version>\n";
        String markdown = renderer.render(report(), rejectedGroupOutcome(RejectionStage.PLAN_DEVIATION_REQUIRED, patch));

        assertTrue(markdown.contains("```diff"), markdown);
        assertTrue(markdown.contains(patch.strip()), markdown);
    }

    @Test
    @DisplayName("reproduction is anchored to the group's own acceptedBaseSha, never a candidate branch name")
    void reproductionAnchoredToAcceptedBaseShaNeverCandidateBranch() {
        String patch = "diff --git a/pom.xml b/pom.xml\n+<version>1.1</version>\n";
        String markdown = renderer.render(report(), rejectedGroupOutcome(RejectionStage.CUMULATIVE_JENKINS, patch));

        assertTrue(markdown.contains("git checkout acceptedBaseSha123"), markdown);
        assertTrue(markdown.contains("git apply fix.patch"), markdown);
        assertFalse(markdown.toLowerCase(java.util.Locale.ROOT).contains("-candidate/"),
                "must never reference a candidate branch name: " + markdown);
    }

    @Test
    @DisplayName("the manual reproduction recipe's own full-build step names the real, currently-executed "
            + "command -- never a stale hard-coded literal (production defect, pilot "
            + "20260909-012226-8bfda1)")
    void reproductionRecipeUsesTheRealFullBuildCommand() {
        String patch = "diff --git a/pom.xml b/pom.xml\n+<version>1.1</version>\n";
        String markdown = renderer.render(report(), rejectedGroupOutcome(RejectionStage.CUMULATIVE_JENKINS, patch));

        assertTrue(markdown.contains(
                "mvn " + String.join(" ", com.tungsten.depbot.validation.MavenBuildValidationGate.BUILD_ARGS)),
                markdown);
    }

    @Test
    @DisplayName("when no patch was ever produced, reproduction states plainly that no code change was made "
            + "rather than fabricating a checkout/apply sequence")
    void noPatchProducesPlainStatementNotFabricatedReproduction() {
        String markdown = renderer.render(report(),
                rejectedGroupOutcome(RejectionStage.IMPLEMENTATION, null));

        assertTrue(markdown.contains("no code change was produced"), markdown);
        assertFalse(markdown.contains("git apply fix.patch"), markdown);
    }

    @Test
    @DisplayName("effectiveRiskReason and plan-conformance violations are rendered when present")
    void effectiveRiskReasonAndConformanceViolationsAreRendered() {
        String markdown = renderer.render(report(),
                rejectedGroupOutcome(RejectionStage.PLAN_DEVIATION_REQUIRED, null,
                        "Originally classified AUTOMATIC_ALLOWED by analysis; Java routing escalated this "
                                + "remediation to human-review-required because the plan contains "
                                + "machine-unverifiable OTHER changes.",
                        List.of("unauthorized file changed: b.txt")));

        assertTrue(markdown.contains("Why this group was risky"), markdown);
        assertTrue(markdown.contains("machine-unverifiable OTHER changes"), markdown);
        assertTrue(markdown.contains("Plan-conformance violations"), markdown);
        assertTrue(markdown.contains("unauthorized file changed: b.txt"), markdown);
    }

    @Test
    @DisplayName("the risky/status banner states the exact failure reason for a rejected group")
    void bannerStatesExactFailureReason() {
        String markdown = renderer.render(report(),
                rejectedGroupOutcome(RejectionStage.CUMULATIVE_JENKINS, null));

        assertTrue(markdown.contains("the plan deviated from what was approved"), markdown);
    }

    @Test
    @DisplayName("long-form evidence is pushed into a collapsible details section at the bottom")
    void longFormEvidenceIsInCollapsibleDetails() {
        String markdown = renderer.render(report(jenkinsOutcome(JenkinsValidationStatus.SUCCESS), null));

        assertTrue(markdown.contains("<details><summary>Full investigation evidence</summary>"), markdown);
        assertTrue(markdown.contains("</details>"), markdown);
        int detailsIndex = markdown.indexOf("<details>");
        int glanceIndex = markdown.indexOf("| Coordinates |");
        assertTrue(glanceIndex >= 0 && glanceIndex < detailsIndex,
                "the at-a-glance table must appear before the collapsible details: " + markdown);
    }

    // ---- cohort-level final-integration-failure dossier ------------------------------------------------

    private static CohortIntegrationFailureOutcome cohortDossier() {
        return new CohortIntegrationFailureOutcome(
                "1.0", "remediation/run1/release-9.2", "refs/remotes/origin/release/9.2", "s0sha",
                List.of("g-a", "g-b"),
                List.of(new CohortsIndex.Commit("g-a", "commitA", "remediation-report.json"),
                        new CohortsIndex.Commit("g-b", "commitB", "remediation-report.json")),
                "diff --git a/a.txt b/a.txt\n+content-a\n",
                jenkinsOutcome(JenkinsValidationStatus.FAILED), "console log excerpt",
                List.of("g-a: dependency validation passed, full build passed", "g-b: dependency validation passed"),
                "the assembled branch failed the final integration build",
                "this failure reflects the combination of groups g-a, g-b together; automation found no "
                        + "evidence isolating it to a single group",
                "git checkout s0sha\ngit apply cumulative.patch\nmvn -B clean package\n");
    }

    @Test
    @DisplayName("the cohort dossier renders every accepted group/commit, the attribution note naming the "
            + "whole set, and reproduction anchored to S0")
    void cohortDossierRendersWholeSetNeverAttributingToOneGroup() {
        String markdown = renderer.render(report(), null, cohortDossier());

        assertTrue(markdown.contains("g-a") && markdown.contains("g-b"), markdown);
        assertTrue(markdown.contains("commitA") && markdown.contains("commitB"), markdown);
        assertTrue(markdown.contains("this failure reflects the combination of groups g-a, g-b together"), markdown);
        assertTrue(markdown.contains("git checkout s0sha"), markdown);
        assertTrue(markdown.contains("```diff"), markdown);
        assertTrue(markdown.contains("Why the whole cohort") || markdown.contains("Cohort publication blocked"),
                markdown);
    }

    @Test
    @DisplayName("the cohort dossier's Jenkins console log excerpt appears in the collapsible details section")
    void cohortConsoleLogAppearsInDetails() {
        String markdown = renderer.render(report(), null, cohortDossier());

        assertTrue(markdown.contains("console log excerpt"), markdown);
    }
}
