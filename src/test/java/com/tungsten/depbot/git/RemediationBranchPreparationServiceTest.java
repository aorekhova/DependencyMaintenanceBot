package com.tungsten.depbot.git;

import com.tungsten.depbot.remediation.DependencyNotFoundException;
import com.tungsten.depbot.remediation.LibraryRemediation;
import com.tungsten.depbot.remediation.RemediationPlan;
import com.tungsten.depbot.remediation.RemediationPlanJsonRenderer;
import com.tungsten.depbot.remediation.RemediationSourceException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemediationBranchPreparationServiceTest {

    @TempDir
    Path tempDir;

    private Path planPath() {
        return tempDir.resolve("remediation-plan.json");
    }

    private void writePlan(RemediationPlan plan) throws IOException {
        Files.writeString(planPath(), new RemediationPlanJsonRenderer().render(plan), StandardCharsets.UTF_8);
    }

    private static LibraryRemediation library(String artifactId) {
        return new LibraryRemediation("g", artifactId, "1.0", "2.0", "CRITICAL", List.of("CVE-1"), null);
    }

    private static LibraryRemediation library(String groupId, String artifactId, String severity) {
        return new LibraryRemediation(groupId, artifactId, "1.0", "2.0", severity, List.of("CVE-1"), null);
    }

    private static RemediationPlan planWith(
            List<LibraryRemediation> critical, List<LibraryRemediation> high,
            List<LibraryRemediation> medium, List<LibraryRemediation> low) {
        return new RemediationPlan("2026-08-04T10:00:00Z", "2026-08-04T09:00:00Z",
                RemediationPlan.CURRENT_VERSION, critical, high, medium, low, List.of());
    }

    private RemediationBranchPreparationService service(Path repoPath) {
        return new RemediationBranchPreparationService(
                planPath(), () -> new GitWorktreeConfig(repoPath), new GitCommandRunner());
    }

    private RemediationBranchPreparationService service(Path repoPath, String runId) {
        return new RemediationBranchPreparationService(
                planPath(), () -> new GitWorktreeConfig(repoPath), new GitCommandRunner(), () -> runId);
    }

    @Test
    @DisplayName("a missing remediation plan throws RemediationSourceException")
    void missingPlanThrows() {
        assertThrows(RemediationSourceException.class, () -> service(tempDir).prepareBranches());
    }

    @Test
    @DisplayName("a malformed remediation plan throws RemediationSourceException")
    void malformedPlanThrows() throws IOException {
        Files.writeString(planPath(), "{ not valid json", StandardCharsets.UTF_8);
        assertThrows(RemediationSourceException.class, () -> service(tempDir).prepareBranches());
    }

    @Test
    @DisplayName("when every group is empty, no git command is run but a run id is still assigned")
    void allGroupsEmptySkipsGit() throws Exception {
        writePlan(planWith(List.of(), List.of(), List.of(), List.of()));
        // repoPath points at a plain (non-git) directory: if git were invoked, fetch would throw.
        RemediationBranchOutcome outcome = service(tempDir, "run1").prepareBranches();

        assertEquals("run1", outcome.runId());
        assertEquals(null, outcome.baseCommitSha());
        assertTrue(outcome.created().isEmpty());
        assertEquals(List.of("critical", "high", "medium", "low"), outcome.emptyGroups());
        assertTrue(outcome.failures().isEmpty());
    }

    @Test
    @DisplayName("branches for non-empty severities are all created from the same base SHA, never checked out")
    void createsBranchesFromSameBaseShaWithoutCheckingOut() throws Exception {
        Path repo = GitTestRepos.createOriginAndClone(tempDir);
        GitCommandRunner git = new GitCommandRunner();
        git.fetch(repo, "origin");
        String expectedSha = git.revParse(repo, "origin/master");

        writePlan(planWith(List.of(library("a")), List.of(library("b")), List.of(), List.of()));

        RemediationBranchOutcome outcome = service(repo, "run1").prepareBranches();

        assertEquals("run1", outcome.runId());
        assertEquals(expectedSha, outcome.baseCommitSha());
        assertEquals(2, outcome.created().size());
        assertEquals(List.of("medium", "low"), outcome.emptyGroups());
        assertTrue(outcome.failures().isEmpty());

        for (CreatedBranch branch : outcome.created()) {
            assertEquals(expectedSha, git.revParse(repo, branch.branchName()));
        }
        assertEquals("master", git.currentBranch(repo), "branch preparation must never switch the checkout");
    }

    @Test
    @DisplayName("branch names include the run id and the severity")
    void branchNamesIncludeRunIdAndSeverity() throws Exception {
        Path repo = GitTestRepos.createOriginAndClone(tempDir);
        writePlan(planWith(List.of(library("a")), List.of(), List.of(), List.of()));

        RemediationBranchOutcome outcome = service(repo, "run1").prepareBranches();

        assertEquals("remediation/run1/critical", outcome.created().get(0).branchName());
    }

    @Test
    @DisplayName("repeated runs against the same repository do not conflict")
    void repeatedRunsDoNotConflict() throws Exception {
        Path repo = GitTestRepos.createOriginAndClone(tempDir);
        writePlan(planWith(List.of(library("a")), List.of(), List.of(), List.of()));

        RemediationBranchOutcome first = service(repo, "run1").prepareBranches();
        RemediationBranchOutcome second = service(repo, "run2").prepareBranches();

        assertTrue(first.failures().isEmpty());
        assertTrue(second.failures().isEmpty());
        assertEquals("remediation/run1/critical", first.created().get(0).branchName());
        assertEquals("remediation/run2/critical", second.created().get(0).branchName());
    }

    @Test
    @DisplayName("the default run id generator produces distinct, git-ref-safe ids")
    void defaultRunIdGeneratorProducesDistinctSafeIds() {
        String first = RemediationBranchPreparationService.generateRunId();
        String second = RemediationBranchPreparationService.generateRunId();

        assertTrue(first.matches("[0-9A-Za-z-]+"), "run id must only contain characters safe in a branch name: " + first);
        assertTrue(!first.contains(":"), "a colon is not valid in a git branch name");
        assertTrue(!first.equals(second), "the random suffix should make two calls distinct in practice");
    }

    @Test
    @DisplayName("a pre-existing branch name fails only its own severity; other severities still succeed")
    void preExistingBranchFailsOnlyThatSeverity() throws Exception {
        Path repo = GitTestRepos.createOriginAndClone(tempDir);
        GitCommandRunner git = new GitCommandRunner();
        git.fetch(repo, "origin");
        String sha = git.revParse(repo, "origin/master");
        git.createBranch(repo, "remediation/run1/critical", sha);

        writePlan(planWith(List.of(library("a")), List.of(library("b")), List.of(), List.of()));

        RemediationBranchOutcome outcome = service(repo, "run1").prepareBranches();

        assertEquals(1, outcome.failures().size());
        assertEquals("critical", outcome.failures().get(0).group());
        assertEquals(1, outcome.created().size());
        assertEquals("high", outcome.created().get(0).severity());
    }

    @Test
    @DisplayName("a pilot --dependency filter creates exactly one branch, in the library's real severity")
    void pilotFilterCreatesExactlyOneBranchInRealSeverity() throws Exception {
        Path repo = GitTestRepos.createOriginAndClone(tempDir);
        writePlan(planWith(
                List.of(library("g", "critical-lib", "CRITICAL")),
                List.of(library("com.fasterxml.jackson.core", "jackson-databind", "HIGH")),
                List.of(library("g", "medium-lib", "MEDIUM")),
                List.of(library("g", "low-lib", "LOW"))));

        RemediationBranchOutcome outcome =
                service(repo, "run1").prepareBranches("com.fasterxml.jackson.core", "jackson-databind");

        assertEquals(1, outcome.created().size());
        assertEquals("high", outcome.created().get(0).severity());
        assertEquals("remediation/run1/high", outcome.created().get(0).branchName());
        assertEquals(List.of("critical", "medium", "low"), outcome.emptyGroups());
        assertTrue(outcome.failures().isEmpty());

        assertEquals(1, outcome.plan().high().size());
        assertEquals("jackson-databind", outcome.plan().high().get(0).artifactId());
        assertTrue(outcome.plan().critical().isEmpty());
        assertTrue(outcome.plan().medium().isEmpty());
        assertTrue(outcome.plan().low().isEmpty());
    }

    @Test
    @DisplayName("an unknown --dependency is rejected before git is ever touched")
    void pilotFilterForUnknownDependencyNeverTouchesGit() throws Exception {
        writePlan(planWith(List.of(library("a")), List.of(), List.of(), List.of()));
        // tempDir is a plain, non-git directory: if fetch were ever attempted it would fail with a
        // GitCommandException instead, which this test would then not see.

        assertThrows(DependencyNotFoundException.class,
                () -> service(tempDir, "run1").prepareBranches("does.not", "exist"));
    }
}
