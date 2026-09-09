package com.tungsten.depbot.claude;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.time.Duration;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClaudeCommandTest {

    private static final ClaudeConfig OPUS =
            new ClaudeConfig("claude", "opus", 30, Duration.ofSeconds(600));

    private static List<String> assessmentCommand() {
        return ClaudeCommand.build(OPUS, ClaudeToolPolicy.forAssessment());
    }

    @Test
    @DisplayName("the executable comes first, so the command can go straight to a ProcessBuilder")
    void executableComesFirst() {
        assertEquals("claude", assessmentCommand().get(0));
    }

    @Test
    @DisplayName("the model is passed as its own argument, exactly as configured")
    void modelIsPassedThrough() {
        List<String> command = assessmentCommand();

        int index = command.indexOf("--model");
        assertTrue(index >= 0, "expected a --model flag");
        assertEquals("opus", command.get(index + 1));
    }

    @Test
    @DisplayName("a configured non-default model is passed through unchanged")
    void configuredModelIsPassedThrough() {
        List<String> command = ClaudeCommand.build(
                new ClaudeConfig("claude", "claude-opus-5", 30, Duration.ofSeconds(600)),
                ClaudeToolPolicy.forAssessment());

        assertEquals("claude-opus-5", command.get(command.indexOf("--model") + 1));
    }

    @Test
    @DisplayName("output is requested as JSON")
    void jsonOutputIsRequested() {
        List<String> command = assessmentCommand();

        int index = command.indexOf("--output-format");
        assertTrue(index >= 0, "expected an --output-format flag");
        assertEquals("json", command.get(index + 1));
    }

    @Test
    @DisplayName("the run is non-interactive")
    void runsNonInteractively() {
        assertTrue(assessmentCommand().contains("--print"));
    }

    @Test
    @DisplayName("max turns defaults to the configured number")
    void maxTurnsIsPassed() {
        List<String> command = ClaudeCommand.build(
                new ClaudeConfig("claude", "opus", 7, Duration.ofSeconds(600)),
                ClaudeToolPolicy.forAssessment());

        assertEquals("7", command.get(command.indexOf("--max-turns") + 1));
    }

    @Test
    @DisplayName("a phase may override max turns without changing the operator's configuration")
    void maxTurnsCanBeOverriddenPerInvocation() {
        List<String> command = ClaudeCommand.build(OPUS, ClaudeToolPolicy.forImplementation(), 55);

        assertEquals("55", command.get(command.indexOf("--max-turns") + 1));
        assertEquals(30, OPUS.maxTurns(), "the config itself must not be mutated by an override");
    }

    @Test
    @DisplayName("a non-positive turn limit is rejected rather than passed to the CLI")
    void nonPositiveMaxTurnsIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> ClaudeCommand.build(OPUS, ClaudeToolPolicy.forAssessment(), 0));
        assertThrows(IllegalArgumentException.class,
                () -> ClaudeCommand.build(OPUS, ClaudeToolPolicy.forAssessment(), -1));
    }

    @ParameterizedTest
    @EnumSource(ClaudePhase.class)
    @DisplayName("only git push is disallowed at the tool level in every phase -- fetch/remote/other git is not")
    void onlyGitPushIsDisallowedInEveryPhase(ClaudePhase phase) {
        List<String> command = ClaudeCommand.build(OPUS, ClaudeToolPolicy.forPhase(phase));
        String disallowed = command.get(command.indexOf("--disallowedTools") + 1);

        assertTrue(disallowed.contains("Bash(git push:*)"), disallowed);
        assertFalse(disallowed.contains("Bash(git fetch:*)"), disallowed);
        assertFalse(disallowed.contains("Bash(git remote:*)"), disallowed);
        assertFalse(disallowed.contains("Bash(git:*)"), disallowed);
    }

    @Test
    @DisplayName("--allowedTools is its own argument, and the assessment gets a full developer environment including git")
    void assessmentGetsAFullDeveloperEnvironment() {
        List<String> command = assessmentCommand();
        int index = command.indexOf("--allowedTools");
        assertTrue(index >= 0, "expected an --allowedTools flag");
        String allowed = command.get(index + 1);

        assertTrue(allowed.contains("Bash"), allowed);
        assertTrue(allowed.contains("Read"), allowed);
        assertTrue(allowed.contains("Glob"), allowed);
        assertTrue(allowed.contains("Grep"), allowed);
        assertTrue(allowed.contains("WebSearch"), allowed);
        assertTrue(allowed.contains("WebFetch"), allowed);
    }

    @Test
    @DisplayName("the assessment cannot edit anything, so it can never leave a change on a stray branch")
    void assessmentCannotEdit() {
        List<String> command = assessmentCommand();
        String allowed = command.get(command.indexOf("--allowedTools") + 1);
        String disallowed = command.get(command.indexOf("--disallowedTools") + 1);

        assertFalse(allowed.contains("Edit"), allowed);
        assertFalse(allowed.contains("Write"), allowed);
        assertTrue(disallowed.contains("Edit"), disallowed);
        assertTrue(disallowed.contains("Write"), disallowed);
    }

    @Test
    @DisplayName("the implementation may edit files, since remediation is not POM-only")
    void implementationMayEdit() {
        List<String> command = ClaudeCommand.build(OPUS, ClaudeToolPolicy.forImplementation());
        String allowed = command.get(command.indexOf("--allowedTools") + 1);

        assertTrue(allowed.contains("Edit"), allowed);
        assertTrue(allowed.contains("Write"), allowed);
        assertTrue(allowed.contains("Bash"),
                "the implementation must be able to run Maven and confirm the real dependency state "
                        + "before editing, through an ordinary shell rather than a pinned command");
    }

    @ParameterizedTest
    @EnumSource(ClaudePhase.class)
    @DisplayName("permissions are never skipped, in either phase")
    void permissionsAreNeverSkipped(ClaudePhase phase) {
        String command = String.join(" ", ClaudeCommand.build(OPUS, ClaudeToolPolicy.forPhase(phase)))
                .toLowerCase(Locale.ROOT);

        assertFalse(command.contains("dangerously"), command);
        assertFalse(command.contains("skip-permissions"), command);
        assertFalse(command.contains("bypasspermissions"), command);
    }

    @ParameterizedTest
    @EnumSource(ClaudePhase.class)
    @DisplayName("no fallback or secondary model is ever passed")
    void noFallbackModelIsPassed(ClaudePhase phase) {
        List<String> command = ClaudeCommand.build(OPUS, ClaudeToolPolicy.forPhase(phase));

        assertFalse(command.contains("--fallback-model"));
        assertEquals(1, command.stream().filter("--model"::equals).count(),
                "exactly one model must be named, so there is nothing to silently fall back to");
    }

    @ParameterizedTest
    @EnumSource(ClaudePhase.class)
    @DisplayName("the prompt is not an argument, so it can never hit a command-line length limit")
    void promptIsNotAnArgument(ClaudePhase phase) {
        List<String> command = ClaudeCommand.build(OPUS, ClaudeToolPolicy.forPhase(phase));

        // executable + --print + five flag/value pairs (output-format, model, max-turns,
        // allowedTools, disallowedTools)
        assertEquals(12, command.size(),
                "nothing but the executable and its flags belongs on the command line: " + command);
        assertFalse(String.join(" ", command).contains("Remediation task"),
                "the task description must never appear as an argument");
    }

    // ---- resuming a session for the assessment finalization call -----------------------------------

    @Test
    @DisplayName("no --resume is added when there is no session id to resume")
    void noResumeArgumentWithoutASessionId() {
        List<String> command = ClaudeCommand.build(
                OPUS, ClaudeToolPolicy.forAssessmentFinalization(), 8, null);

        assertFalse(command.contains("--resume"), command.toString());
    }

    @Test
    @DisplayName("a blank session id is treated the same as none at all")
    void blankResumeSessionIdAddsNoResumeArgument() {
        List<String> command = ClaudeCommand.build(
                OPUS, ClaudeToolPolicy.forAssessmentFinalization(), 8, "   ");

        assertFalse(command.contains("--resume"), command.toString());
    }

    @Test
    @DisplayName("--resume is added right after the session id, when one is known")
    void resumeArgumentIsAddedWithTheSessionId() {
        List<String> command = ClaudeCommand.build(
                OPUS, ClaudeToolPolicy.forAssessmentFinalization(), 8, "sess-real-1234");

        int index = command.indexOf("--resume");
        assertTrue(index >= 0, command.toString());
        assertEquals("sess-real-1234", command.get(index + 1));
    }

    @Test
    @DisplayName("the three-arg overload never resumes anything, matching its previous behaviour")
    void threeArgOverloadNeverResumes() {
        List<String> command = ClaudeCommand.build(OPUS, ClaudeToolPolicy.forAssessment(), 30);

        assertFalse(command.contains("--resume"), command.toString());
    }
}
