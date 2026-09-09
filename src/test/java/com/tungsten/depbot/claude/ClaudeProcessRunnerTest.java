package com.tungsten.depbot.claude;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClaudeProcessRunnerTest {

    @TempDir
    Path tempDir;

    private final ClaudeProcessRunner runner = new ClaudeProcessRunner();

    private Path workingDirectory() throws Exception {
        Path directory = tempDir.resolve("worktree");
        Files.createDirectories(directory);
        return directory;
    }

    private Path promptFile(String content) throws Exception {
        Path prompt = tempDir.resolve("prompt.md");
        Files.writeString(prompt, content, StandardCharsets.UTF_8);
        return prompt;
    }

    private ClaudeInvocation run(FakeClaude fake, Duration timeout) throws Exception {
        ClaudeConfig config = new ClaudeConfig(fake.executable().toString(), "opus", 30, timeout);
        return runner.run(
                ClaudeCommand.build(config, ClaudeToolPolicy.forImplementation()),
                workingDirectory(),
                promptFile("the task prompt"),
                tempDir.resolve("stdout.json"),
                tempDir.resolve("stderr.log"),
                timeout);
    }

    @Test
    @DisplayName("a clean run reports exit code zero and captures stdout and stderr to files")
    void cleanRunCapturesStreams() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir)
                .printing("{\"result\":\"done\"}")
                .printingToStderr("a warning")
                .build();

        ClaudeInvocation invocation = run(fake, Duration.ofSeconds(60));

        assertTrue(invocation.started());
        assertFalse(invocation.timedOut());
        assertEquals(0, invocation.exitCode());
        assertTrue(invocation.succeeded());
        assertTrue(Files.readString(tempDir.resolve("stdout.json")).contains("done"));
        assertTrue(Files.readString(tempDir.resolve("stderr.log")).contains("a warning"));
    }

    @Test
    @DisplayName("the prompt reaches the process on standard input rather than as an argument")
    void promptArrivesOnStandardInput() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir).build();

        run(fake, Duration.ofSeconds(60));

        assertTrue(fake.recordedStdin().contains("the task prompt"), fake.recordedStdin());
        assertFalse(fake.recordedArgs().contains("the task prompt"), fake.recordedArgs());
    }

    @Test
    @DisplayName("the process runs in the given working directory")
    void runsInTheGivenWorkingDirectory() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir).build();

        run(fake, Duration.ofSeconds(60));

        assertEquals(workingDirectory().toRealPath().toString(),
                Path.of(fake.recordedWorkingDirectory()).toRealPath().toString());
    }

    @Test
    @DisplayName("a non-zero exit code is reported as-is, not treated as success")
    void nonZeroExitIsReported() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir).exitingWith(3).build();

        ClaudeInvocation invocation = run(fake, Duration.ofSeconds(60));

        assertEquals(3, invocation.exitCode());
        assertFalse(invocation.succeeded());
    }

    @Test
    @DisplayName("a process that outlasts the timeout is killed and reported as timed out")
    void slowProcessTimesOut() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir).sleepingFor(30).build();

        ClaudeInvocation invocation = run(fake, Duration.ofSeconds(1));

        assertTrue(invocation.timedOut());
        assertNull(invocation.exitCode(), "a killed process has no meaningful exit code");
        assertFalse(invocation.succeeded());
    }

    @Test
    @DisplayName("a missing executable is reported as a start failure naming the environment variable")
    void missingExecutableIsReported() throws Exception {
        ClaudeConfig config = new ClaudeConfig(
                tempDir.resolve("definitely-not-here").toString(), "opus", 30, Duration.ofSeconds(5));

        ClaudeInvocation invocation = runner.run(
                ClaudeCommand.build(config, ClaudeToolPolicy.forImplementation()),
                workingDirectory(), promptFile("prompt"),
                tempDir.resolve("stdout.json"), tempDir.resolve("stderr.log"), Duration.ofSeconds(5));

        assertFalse(invocation.started());
        assertTrue(invocation.startFailure().contains(ClaudeConfig.CLAUDE_EXECUTABLE),
                invocation.startFailure());
    }

    @Test
    @DisplayName("the arguments the process receives are the ones the command builder produced")
    void argumentsArePassedThrough() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir).build();

        run(fake, Duration.ofSeconds(60));

        String args = fake.recordedArgs();
        assertTrue(args.contains("--model"), args);
        assertTrue(args.contains("opus"), args);
        assertTrue(args.contains("--output-format"), args);
        assertTrue(args.contains("json"), args);
        assertTrue(args.contains("--max-turns"), args);
        assertTrue(args.contains("Bash(git push:*)"), args);
    }

    @Test
    @DisplayName("the command is a list of arguments, never a single shell string")
    void commandIsNotAShellString() {
        List<String> command = ClaudeCommand.build(
                new ClaudeConfig("claude", "opus", 30, Duration.ofSeconds(60)),
                ClaudeToolPolicy.forImplementation());

        assertTrue(command.size() > 1,
                "a single-element command would mean the arguments had been joined into a shell string");
    }
}
