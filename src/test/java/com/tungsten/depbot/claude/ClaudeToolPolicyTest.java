package com.tungsten.depbot.claude;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClaudeToolPolicyTest {

    @ParameterizedTest
    @EnumSource(ClaudePhase.class)
    @DisplayName("both phases get a full developer environment: an unrestricted shell, file access, and web tools")
    void bothPhasesGetTheFullDeveloperEnvironment(ClaudePhase phase) {
        List<String> allowed = ClaudeToolPolicy.forPhase(phase).allowedTools();

        assertTrue(allowed.contains("Bash"), "a bare Bash entry is deliberate now: Maven, curl, package "
                + "tooling and anything else a real investigation or fix needs must simply be available, "
                + "not enumerated command by command");
        assertTrue(allowed.contains("Read"));
        assertTrue(allowed.contains("Glob"));
        assertTrue(allowed.contains("Grep"));
        assertTrue(allowed.contains("WebSearch"));
        assertTrue(allowed.contains("WebFetch"));
    }

    @ParameterizedTest
    @EnumSource(ClaudePhase.class)
    @DisplayName("git is available locally in both phases -- only publishing is refused")
    void gitIsAvailableLocallyInBothPhases(ClaudePhase phase) {
        ClaudeToolPolicy policy = ClaudeToolPolicy.forPhase(phase);

        assertTrue(policy.allowedTools().contains("Bash"),
                "local git (log, show, diff, grep, blame, for-each-ref, checkout, switch, branch, reset, "
                        + "restore, commit) reaches Claude through the bare Bash entry, the same as any "
                        + "other shell command -- there is no curated allow-list of individual git "
                        + "subcommands to keep in sync");
        assertFalse(policy.disallowedTools().stream().anyMatch(entry -> entry.equals("Bash(git:*)")),
                "git as a whole must not be blocked -- only publishing is");
    }

    @ParameterizedTest
    @EnumSource(ClaudePhase.class)
    @DisplayName("only git push is refused, in both phases -- publishing, and nothing else about git")
    void onlyGitPushIsRefused(ClaudePhase phase) {
        ClaudeToolPolicy policy = ClaudeToolPolicy.forPhase(phase);

        assertTrue(policy.disallowedTools().contains("Bash(git push:*)"), policy.disallowedTools().toString());
        assertEquals(List.of("Bash(git push:*)"), ClaudeToolPolicy.FORBIDDEN_GIT_PUBLISHING);
    }

    @ParameterizedTest
    @EnumSource(ClaudePhase.class)
    @DisplayName("git fetch and git remote are not refused -- they read from or reconfigure only the local checkout")
    void fetchAndRemoteAreNotRefused(ClaudePhase phase) {
        ClaudeToolPolicy policy = ClaudeToolPolicy.forPhase(phase);

        assertFalse(policy.disallowedTools().contains("Bash(git fetch:*)"), policy.disallowedTools().toString());
        assertFalse(policy.disallowedTools().contains("Bash(git remote:*)"), policy.disallowedTools().toString());
    }

    @ParameterizedTest
    @EnumSource(ClaudePhase.class)
    @DisplayName("Maven is not pinned to any one goal -- the whole point is no per-command allow-list")
    void mavenIsNotPinnedToASingleGoal(ClaudePhase phase) {
        List<String> allowed = ClaudeToolPolicy.forPhase(phase).allowedTools();

        assertFalse(allowed.stream().anyMatch(entry -> entry.contains("mvn")),
                "Maven reaches Claude only through the bare Bash entry, never through a command-specific "
                        + "allow-list entry: " + allowed);
    }

    @ParameterizedTest
    @EnumSource(ClaudePhase.class)
    @DisplayName("no profile hints at skipping permissions")
    void noProfileHintsAtSkippingPermissions(ClaudePhase phase) {
        String allowed = ClaudeToolPolicy.forPhase(phase).allowedArgument().toLowerCase(Locale.ROOT);

        assertFalse(allowed.contains("dangerously"), allowed);
        assertFalse(allowed.contains("bypasspermissions"), allowed);
    }

    @Test
    @DisplayName("only the implementation profile permits editing, even though both have full shell access")
    void onlyImplementationPermitsEditing() {
        assertFalse(ClaudeToolPolicy.forAssessment().permitsEditing());
        assertTrue(ClaudeToolPolicy.forImplementation().permitsEditing());

        assertFalse(ClaudeToolPolicy.forAssessment().allowedTools().contains("Edit"));
        assertTrue(ClaudeToolPolicy.forAssessment().disallowedTools().contains("Edit"));
    }

    @Test
    @DisplayName("the implementation finalization profile is tool-free, exactly like the other two finalizations")
    void implementationFinalizationProfileIsToolFree() {
        ClaudeToolPolicy policy = ClaudeToolPolicy.forImplementationFinalization();

        assertFalse(policy.permitsEditing());
        assertTrue(policy.allowedTools().isEmpty(),
                "the evidence is fully precomputed and embedded in the prompt, so there is nothing left "
                        + "for a tool call to do here -- this is the actual fix for the production bug "
                        + "where a Bash-permitted finalization call burned its whole turn budget on tool calls");
        assertTrue(policy.disallowedTools().contains("Bash"));
        assertTrue(policy.disallowedTools().contains("Edit"));
        assertTrue(policy.disallowedTools().contains("Write"));
        assertEquals(ClaudeToolPolicy.forAssessmentFinalization(), policy,
                "tool-free, editing refused -- the same shape as the other two finalizations");
    }

    @Test
    @DisplayName("the arguments are comma-separated, matching what the CLI flags take")
    void argumentsAreCommaSeparated() {
        ClaudeToolPolicy policy = new ClaudeToolPolicy(List.of("Read", "Write"), List.of("Bash(git push:*)"));

        assertEquals("Read,Write", policy.allowedArgument());
        assertEquals("Bash(git push:*)", policy.disallowedArgument());
    }

    @Test
    @DisplayName("a policy is immutable, so a shared profile cannot be edited by one caller")
    void policyIsImmutable() {
        ClaudeToolPolicy policy = ClaudeToolPolicy.forImplementation();

        assertThrows(UnsupportedOperationException.class, () -> policy.allowedTools().add("Bash"));
        assertThrows(UnsupportedOperationException.class, () -> policy.disallowedTools().clear());
    }

    @Test
    @DisplayName("the assessment finalization profile allows no tools at all")
    void assessmentFinalizationProfileAllowsNoTools() {
        ClaudeToolPolicy policy = ClaudeToolPolicy.forAssessmentFinalization();

        assertTrue(policy.allowedTools().isEmpty(), policy.allowedTools().toString());
        for (String tool : ClaudeToolPolicy.DEVELOPER_ACCESS) {
            assertTrue(policy.disallowedTools().contains(tool), policy.disallowedTools().toString());
        }
        for (String tool : ClaudeToolPolicy.EDITING) {
            assertTrue(policy.disallowedTools().contains(tool), policy.disallowedTools().toString());
        }
        assertFalse(policy.permitsEditing());
    }

    @Test
    @DisplayName("forPhase returns the profile named for that phase")
    void forPhaseMatchesTheNamedProfiles() {
        assertEquals(ClaudeToolPolicy.forAssessment(), ClaudeToolPolicy.forPhase(ClaudePhase.ASSESSMENT));
        assertEquals(ClaudeToolPolicy.forImplementation(),
                ClaudeToolPolicy.forPhase(ClaudePhase.IMPLEMENTATION));
    }
}
