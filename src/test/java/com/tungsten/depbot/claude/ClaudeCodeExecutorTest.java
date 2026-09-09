package com.tungsten.depbot.claude;

import com.tungsten.depbot.run.RemediationRunService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers only what {@link ClaudeCodeExecutor} itself does: running one invocation once, in the phase and
 * under the permissions the request names, and reporting whether the process finished cleanly. What the
 * answer means, whether it is worth keeping, and what happens to the working tree afterwards all belong to
 * the phase services above it.
 */
class ClaudeCodeExecutorTest {

    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-08-04T10:00:00Z"), ZoneOffset.UTC);
    private static final String RUN_ID = "run1";

    @TempDir
    Path tempDir;

    private Path runsRoot() {
        return tempDir.resolve("runs");
    }

    private RemediationRunService runService() {
        return new RemediationRunService(FIXED_CLOCK, runsRoot());
    }

    private ClaudeCodeExecutor executor(ClaudeConfig config) {
        return new ClaudeCodeExecutor(config, new ClaudeProcessRunner(), runService(), FIXED_CLOCK);
    }

    private ClaudeConfig config(FakeClaude fake) {
        return new ClaudeConfig(fake.executable().toString(), "opus", 5, Duration.ofSeconds(60));
    }

    // ---------------------------------------------------------------------------------------
    // The phased path: one invoker, either phase, driven entirely by the request handed to it.
    // ---------------------------------------------------------------------------------------

    private Path workspace() throws IOException {
        Path workspace = tempDir.resolve("workspace");
        Files.createDirectories(workspace);
        return workspace;
    }

    private ClaudeRunRequest request(ClaudePhase phase, String prompt, ClaudeConfig config)
            throws IOException {
        return ClaudeRunRequest.of(phase, workspace(), prompt,
                tempDir.resolve("attempts").resolve(phase.directoryName()), config);
    }

    /** A prompt carrying the phase's marker, as a real rendered prompt will. */
    private static String promptFor(ClaudePhase phase) {
        return phase.promptMarker() + "\n\n# " + phase.name() + " task\n\nDo the work.\n";
    }

    @Test
    @DisplayName("a phased run writes its artifacts into the attempt directory the request names")
    void phasedRunWritesArtifactsWhereTheRequestSays() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir)
                .printing("{\"result\":\"assessed\"}")
                .printingToStderr("a note")
                .build();
        ClaudeRunRequest request =
                request(ClaudePhase.ASSESSMENT, promptFor(ClaudePhase.ASSESSMENT), config(fake));

        ClaudeRunOutcome outcome = executor(config(fake)).run(request);

        assertTrue(outcome.completedCleanly());
        Path attempt = request.attemptDirectory();
        assertTrue(Files.readString(attempt.resolve(ClaudeArtifacts.PROMPT_FILE)).contains("ASSESSMENT task"));
        assertTrue(Files.readString(attempt.resolve(ClaudeArtifacts.STDOUT_FILE)).contains("assessed"));
        assertTrue(Files.readString(attempt.resolve(ClaudeArtifacts.STDERR_FILE)).contains("a note"));
        assertEquals("0", Files.readString(attempt.resolve(ClaudeArtifacts.EXIT_CODE_FILE)).strip());
        assertEquals(request.stdoutFile(), attempt.resolve(ClaudeArtifacts.STDOUT_FILE));
    }

    @Test
    @DisplayName("the prompt reaches Claude verbatim, marker and all, with nothing appended")
    void promptReachesClaudeVerbatim() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir).build();
        String prompt = promptFor(ClaudePhase.IMPLEMENTATION);

        executor(config(fake)).run(request(ClaudePhase.IMPLEMENTATION, prompt, config(fake)));

        Path promptFile = tempDir.resolve("attempts").resolve("implementation")
                .resolve(ClaudeArtifacts.PROMPT_FILE);
        assertEquals(prompt, Files.readString(promptFile));
        assertTrue(fake.recordedStdin().contains(ClaudePhase.IMPLEMENTATION.promptMarker()),
                fake.recordedStdin());
    }

    @Test
    @DisplayName("the assessment invocation cannot edit, and the implementation invocation can")
    void eachPhaseReachesClaudeWithItsOwnPermissions() throws Exception {
        FakeClaude assessmentFake = FakeClaude.in(tempDir).named("assess").build();
        FakeClaude implementationFake = FakeClaude.in(tempDir).named("implement").build();

        executor(config(assessmentFake)).run(
                request(ClaudePhase.ASSESSMENT, promptFor(ClaudePhase.ASSESSMENT), config(assessmentFake)));
        executor(config(implementationFake)).run(request(
                ClaudePhase.IMPLEMENTATION, promptFor(ClaudePhase.IMPLEMENTATION), config(implementationFake)));

        String assessmentArgs = assessmentFake.recordedArgs();
        int allowedEnd = assessmentArgs.indexOf("--disallowedTools");
        String assessmentAllowed = assessmentArgs.substring(0, allowedEnd);
        assertFalse(assessmentAllowed.contains("Write"), assessmentArgs);
        assertTrue(assessmentArgs.contains("Bash(git push:*)"), assessmentArgs);

        assertTrue(implementationFake.recordedArgs().contains("Write"), implementationFake.recordedArgs());
    }

    @Test
    @DisplayName("one fake answers each phase differently, keyed on the prompt it actually received")
    void oneFakeAnswersBothPhases() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, "{\"result\":\"my assessment\"}")
                .respondingTo(ClaudePhase.IMPLEMENTATION, "{\"result\":\"my implementation\"}")
                .build();
        ClaudeCodeExecutor executor = executor(config(fake));

        executor.run(request(ClaudePhase.ASSESSMENT, promptFor(ClaudePhase.ASSESSMENT), config(fake)));
        executor.run(request(
                ClaudePhase.IMPLEMENTATION, promptFor(ClaudePhase.IMPLEMENTATION), config(fake)));

        ClaudeResultExtractor extractor = new ClaudeResultExtractor();
        assertEquals("my assessment", extractor.extractFrom(
                tempDir.resolve("attempts").resolve("assessment").resolve(ClaudeArtifacts.STDOUT_FILE)).text());
        assertEquals("my implementation", extractor.extractFrom(
                tempDir.resolve("attempts").resolve("implementation").resolve(ClaudeArtifacts.STDOUT_FILE)).text());
        assertEquals(List.of("assessment", "implementation"), fake.recordedPhaseSequence());
        assertEquals(2, fake.invocationCount());
    }

    @Test
    @DisplayName("a phase can fail on its own while the other still succeeds")
    void aPhaseCanFailIndependently() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, "{\"result\":\"fine\"}", 0)
                .respondingTo(ClaudePhase.IMPLEMENTATION, "{\"result\":\"broke\"}", 3)
                .build();
        ClaudeCodeExecutor executor = executor(config(fake));

        ClaudeRunOutcome assessment = executor.run(
                request(ClaudePhase.ASSESSMENT, promptFor(ClaudePhase.ASSESSMENT), config(fake)));
        ClaudeRunOutcome implementation = executor.run(request(
                ClaudePhase.IMPLEMENTATION, promptFor(ClaudePhase.IMPLEMENTATION), config(fake)));

        assertTrue(assessment.completedCleanly());
        assertFalse(implementation.completedCleanly());
        assertEquals(3, implementation.exitCode());
    }

    @Test
    @DisplayName("a non-zero exit that still wrote a structured result names the reported subtype explicitly")
    void nonZeroExitWithAStructuredSubtypeNamesItExplicitly() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT,
                        "{\"type\":\"result\",\"is_error\":true,\"subtype\":\"error_max_turns\"}", 1)
                .build();

        ClaudeRunOutcome outcome = executor(config(fake))
                .run(request(ClaudePhase.ASSESSMENT, promptFor(ClaudePhase.ASSESSMENT), config(fake)));

        assertFalse(outcome.completedCleanly());
        assertEquals(1, outcome.exitCode());
        assertTrue(outcome.failureReason().contains("exited with code 1"), outcome.failureReason());
        assertTrue(outcome.failureReason().contains("error_max_turns"), outcome.failureReason());
    }

    @Test
    @DisplayName("a non-zero exit with no usable structured output falls back to the generic message alone")
    void nonZeroExitWithNoStructuredOutputStaysGeneric() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, "not JSON at all", 1)
                .build();

        ClaudeRunOutcome outcome = executor(config(fake))
                .run(request(ClaudePhase.ASSESSMENT, promptFor(ClaudePhase.ASSESSMENT), config(fake)));

        assertFalse(outcome.completedCleanly());
        assertTrue(outcome.failureReason().contains("exited with code 1"), outcome.failureReason());
        assertFalse(outcome.failureReason().contains("subtype"), outcome.failureReason());
    }

    @Test
    @DisplayName("a prompt with no phase marker still gets the unscripted default answer")
    void unmarkedPromptGetsTheDefaultAnswer() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir)
                .printing("{\"result\":\"default\"}")
                .respondingTo(ClaudePhase.ASSESSMENT, "{\"result\":\"assessment only\"}")
                .build();
        ClaudeRunRequest unmarked = new ClaudeRunRequest(
                ClaudePhase.ASSESSMENT, workspace(), "a prompt that declares no phase",
                tempDir.resolve("attempts").resolve("assessment"),
                ClaudeToolPolicy.forAssessment(), 5, Duration.ofSeconds(60));

        executor(config(fake)).run(unmarked);

        Path stdout = unmarked.attemptDirectory().resolve(ClaudeArtifacts.STDOUT_FILE);
        assertTrue(Files.readString(stdout).contains("default"), Files.readString(stdout));
        assertEquals(List.of("none"), fake.recordedPhaseSequence());
    }

    @Test
    @DisplayName("a request's own timeout is what applies, not the configured default")
    void requestTimeoutApplies() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir).sleepingFor(30).build();
        ClaudeConfig generousConfig =
                new ClaudeConfig(fake.executable().toString(), "opus", 5, Duration.ofSeconds(600));
        ClaudeRunRequest impatient = new ClaudeRunRequest(
                ClaudePhase.ASSESSMENT, workspace(), promptFor(ClaudePhase.ASSESSMENT),
                tempDir.resolve("attempts").resolve("assessment"),
                ClaudeToolPolicy.forAssessment(), 5, Duration.ofSeconds(1));

        ClaudeRunOutcome outcome = executor(generousConfig).run(impatient);

        assertTrue(outcome.timedOut());
        assertTrue(outcome.failureReason().contains("did not finish within 1s"), outcome.failureReason());
    }

    @Test
    @DisplayName("ClaudeConfig's own phase-specific timeout is what actually kills the real process, "
            + "not just a value recorded on the config")
    void phaseSpecificTimeoutFromConfigActuallyKillsTheRealProcess() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir).sleepingFor(3).build();
        ClaudeConfig config = new ClaudeConfig(fake.executable().toString(), "opus", 5,
                ClaudeConfig.DEFAULT_ANALYSIS_MAX_TURNS, ClaudeConfig.DEFAULT_IMPLEMENTATION_MAX_TURNS,
                ClaudeConfig.DEFAULT_HUMAN_REVIEW_MAX_TURNS,
                ClaudeConfig.DEFAULT_ANALYSIS_FINALIZATION_MAX_TURNS,
                ClaudeConfig.DEFAULT_IMPLEMENTATION_FINALIZATION_MAX_TURNS,
                ClaudeConfig.DEFAULT_HUMAN_REVIEW_FINALIZATION_MAX_TURNS,
                Duration.ofSeconds(60), Duration.ofSeconds(1), Duration.ofSeconds(60), Duration.ofSeconds(60),
                ClaudeConfig.DEFAULT_ANALYSIS_SECOND_ATTEMPT_MAX_TURNS, Duration.ofSeconds(60));

        // Both requests go through the same ClaudeRunRequest.of(...) dispatch a real service uses --
        // neither builds a request with an explicit timeout of its own, so the only thing that can
        // account for a difference in what actually happens to the real process is ClaudeConfig's own
        // per-phase resolution reaching ClaudeProcessRunner's wait/kill.
        ClaudeRunOutcome assessmentOutcome = executor(config)
                .run(request(ClaudePhase.ASSESSMENT, promptFor(ClaudePhase.ASSESSMENT), config));
        ClaudeRunOutcome implementationOutcome = executor(config)
                .run(request(ClaudePhase.IMPLEMENTATION, promptFor(ClaudePhase.IMPLEMENTATION), config));

        assertTrue(assessmentOutcome.timedOut(),
                "assessment's own 1-second timeout must kill a real process that sleeps for 3 seconds");
        assertFalse(implementationOutcome.timedOut(),
                "implementation's own 60-second timeout must let the same 3-second sleep finish normally, "
                        + "proving the two phases are genuinely enforced differently at the process level");
    }

    @Test
    @DisplayName("a request's own turn limit reaches the command line")
    void requestTurnLimitReachesTheCommandLine() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir).build();
        ClaudeRunRequest request = new ClaudeRunRequest(
                ClaudePhase.ASSESSMENT, workspace(), promptFor(ClaudePhase.ASSESSMENT),
                tempDir.resolve("attempts").resolve("assessment"),
                ClaudeToolPolicy.forAssessment(), 42, Duration.ofSeconds(60));

        executor(config(fake)).run(request);

        assertTrue(fake.recordedArgs().contains("42"), fake.recordedArgs());
    }

    @Test
    @DisplayName("a phased run whose workspace is gone fails without starting a process")
    void phasedRunWithMissingWorkspaceFailsWithoutRunning() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir).build();
        ClaudeRunRequest request = new ClaudeRunRequest(
                ClaudePhase.ASSESSMENT, tempDir.resolve("gone"), promptFor(ClaudePhase.ASSESSMENT),
                tempDir.resolve("attempts").resolve("assessment"),
                ClaudeToolPolicy.forAssessment(), 5, Duration.ofSeconds(60));

        ClaudeRunOutcome outcome = executor(config(fake)).run(request);

        assertFalse(outcome.completedCleanly());
        assertEquals(0, fake.invocationCount());
        assertTrue(outcome.failureReason().contains("does not exist"), outcome.failureReason());
    }

    @Test
    @DisplayName("the executor is usable through the shared invoker interface, for either phase")
    void executorIsUsableThroughTheInvokerInterface() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir).build();
        ClaudeInvoker invoker = executor(config(fake));

        assertTrue(invoker.run(
                request(ClaudePhase.ASSESSMENT, promptFor(ClaudePhase.ASSESSMENT), config(fake)))
                .completedCleanly());
    }

    // ---- failures the process itself can produce, whatever the phase --------------------------

    @Test
    @DisplayName("a non-zero exit is not completedCleanly, but the captured output is kept")
    void nonZeroExitIsNotCompletedCleanly() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir)
                .exitingWith(2).printingToStderr("could not edit pom").build();
        ClaudeRunRequest request =
                request(ClaudePhase.IMPLEMENTATION, promptFor(ClaudePhase.IMPLEMENTATION), config(fake));

        ClaudeRunOutcome outcome = executor(config(fake)).run(request);

        assertFalse(outcome.completedCleanly());
        assertEquals(2, outcome.exitCode());
        assertEquals("2", Files.readString(
                request.attemptDirectory().resolve(ClaudeArtifacts.EXIT_CODE_FILE)).strip());
        assertTrue(Files.readString(
                request.attemptDirectory().resolve(ClaudeArtifacts.STDERR_FILE)).contains("could not edit"));
    }

    @Test
    @DisplayName("an unavailable model fails with an explanation naming the model, and substitutes none")
    void unavailableModelFailsWithExplanation() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir)
                .exitingWith(1)
                .printingToStderr("API error: your account does not have access to the requested model")
                .build();

        ClaudeRunOutcome outcome = executor(config(fake))
                .run(request(ClaudePhase.ASSESSMENT, promptFor(ClaudePhase.ASSESSMENT), config(fake)));

        assertFalse(outcome.completedCleanly());
        assertTrue(outcome.failureReason().contains("opus"), outcome.failureReason());
        assertTrue(outcome.failureReason().contains("No weaker model was substituted"),
                outcome.failureReason());
    }

    @Test
    @DisplayName("a missing Claude executable fails with a message naming the variable to fix")
    void missingExecutableFails() throws Exception {
        ClaudeConfig config = new ClaudeConfig(
                tempDir.resolve("not-installed").toString(), "opus", 5, Duration.ofSeconds(30));

        ClaudeRunOutcome outcome = executor(config)
                .run(request(ClaudePhase.ASSESSMENT, promptFor(ClaudePhase.ASSESSMENT), config));

        assertFalse(outcome.completedCleanly());
        assertTrue(outcome.failureReason().contains(ClaudeConfig.CLAUDE_EXECUTABLE),
                outcome.failureReason());
    }
}
