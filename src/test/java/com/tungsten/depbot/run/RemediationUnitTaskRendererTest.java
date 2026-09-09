package com.tungsten.depbot.run;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class RemediationUnitTaskRendererTest {

    private final RemediationUnitTaskRenderer renderer = new RemediationUnitTaskRenderer();

    private static RemediationUnit unit() {
        return new RemediationUnit(
                "run1", "critical__org.bouncycastle__bcprov-jdk18on", "CRITICAL",
                "org.bouncycastle", "bcprov-jdk18on", "1.84", "1.85",
                List.of("CVE-2026-1", "CVE-2026-2"), "remediation/run1/critical",
                "/repo-remediation-run1-critical", "reports/runs/run1/tasks/critical/x.md",
                RemediationUnit.PENDING_STATUS, 0);
    }

    @Test
    @DisplayName("the task names the exact library, current and target versions")
    void namesTheLibraryAndVersions() {
        String task = renderer.render(unit());

        assertTrue(task.contains("org.bouncycastle:bcprov-jdk18on"));
        assertTrue(task.contains("1.84"));
        assertTrue(task.contains("1.85"));
    }

    @Test
    @DisplayName("the task lists every CVE, the branch and the workspace path")
    void listsCvesBranchAndWorktree() {
        String task = renderer.render(unit());

        assertTrue(task.contains("CVE-2026-1"));
        assertTrue(task.contains("CVE-2026-2"));
        assertTrue(task.contains("remediation/run1/critical"));
        assertTrue(task.contains("/repo-remediation-run1-critical"));
    }

    @Test
    @DisplayName("the task explicitly forbids renaming or moving classes")
    void forbidsRenamingOrMovingClasses() {
        String task = renderer.render(unit()).toLowerCase(java.util.Locale.ROOT);
        assertTrue(task.contains("renaming or moving"));
    }

    @Test
    @DisplayName("the task explicitly forbids broad refactors")
    void forbidsBroadRefactors() {
        String task = renderer.render(unit()).toLowerCase(java.util.Locale.ROOT);
        assertTrue(task.contains("refactor"));
    }

    @Test
    @DisplayName("the task explicitly forbids deleting or disabling tests")
    void forbidsDeletingOrDisablingTests() {
        String task = renderer.render(unit()).toLowerCase(java.util.Locale.ROOT);
        assertTrue(task.contains("deleting or disabling"));
    }

    @Test
    @DisplayName("the task explicitly forbids skipTests and equivalent ways of skipping tests")
    void forbidsSkipTests() {
        String task = renderer.render(unit());
        assertTrue(task.contains("skipTests"));
        assertTrue(task.contains("-DskipTests"));
    }

    @Test
    @DisplayName("the task states it does not itself start any work automatically")
    void statesItDoesNotStartWorkAutomatically() {
        String task = renderer.render(unit()).toLowerCase(java.util.Locale.ROOT);
        assertTrue(task.contains("automatically"));
    }

    @Test
    @DisplayName("the task requires checking the current branch via git rev-parse, not git branch")
    void requiresGitRevParseForCurrentBranch() {
        String task = renderer.render(unit());
        assertTrue(task.contains("git rev-parse --abbrev-ref HEAD"), task);
    }

    @Test
    @DisplayName("the task requires running dependency:tree when no direct declaration is found")
    void requiresDependencyTreeWhenNoDirectDeclaration() {
        String task = renderer.render(unit());
        assertTrue(task.contains("dependency:tree"), task);
        assertTrue(task.contains("mvn -o -B dependency:tree -Dincludes=org.bouncycastle:bcprov-jdk18on"), task);
        assertTrue(task.toLowerCase(java.util.Locale.ROOT).contains("could not be confirmed"), task);
    }

    @Test
    @DisplayName("the task forbids cd, command chaining, pipes and output redirection")
    void forbidsCdChainingPipesAndRedirection() {
        String task = renderer.render(unit());
        assertTrue(task.contains("never run `cd`"), task);
        assertTrue(task.contains("&&"), task);
        assertTrue(task.contains("never use pipes"), task);
        assertTrue(task.contains("redirection"), task);
        assertTrue(task.contains("own separate tool call"), task);
    }

    @Test
    @DisplayName("the task forbids every Maven goal other than dependency:tree")
    void forbidsOtherMavenGoals() {
        String task = renderer.render(unit());
        assertTrue(task.contains("`compile`"), task);
        assertTrue(task.contains("`test`"), task);
        assertTrue(task.contains("`package`"), task);
        assertTrue(task.contains("`install`"), task);
        assertTrue(task.contains("`deploy`"), task);
        assertTrue(task.contains("-DoutputFile"), task);
    }

    @Test
    @DisplayName("the task tells Claude it already runs with the workspace path as its working directory")
    void statesWorkingDirectoryIsAlreadySet() {
        String task = renderer.render(unit());
        assertTrue(task.contains("working directory set to the workspace path"), task);
    }

    @Test
    @DisplayName("a unit with no CVEs at all is still rendered, saying so explicitly")
    void noCvesIsStatedExplicitly() {
        RemediationUnit noCves = new RemediationUnit(
                "run1", "low__g__a", "LOW", "g", "a", "1.0", "2.0", List.of(), "remediation/run1/low",
                "/repo-remediation-run1-low", "reports/runs/run1/tasks/low/g__a.md",
                RemediationUnit.PENDING_STATUS, 0);

        String task = renderer.render(noCves);
        assertTrue(task.contains("Not provided"));
    }
}
