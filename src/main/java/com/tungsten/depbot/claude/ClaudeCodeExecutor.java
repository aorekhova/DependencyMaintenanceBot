package com.tungsten.depbot.claude;

import com.tungsten.depbot.run.RemediationRunService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;

/**
 * Runs Claude Code once, for either phase.
 *
 * <p>This class only knows about running the agent and capturing what it did -- writing
 * {@code prompt.md}, invoking the process, saving {@code exit-code.txt}, and reporting whether
 * Claude itself finished cleanly. It has no opinion on whether the result is any good: interpreting
 * an assessment, applying the impact-score policy, the diff-policy check, commit-versus-rollback and
 * rewriting the manifest all belong to the callers above it.
 *
 * <p>Every invocation is attempted exactly once here -- there is no retry at this level either.
 */
public final class ClaudeCodeExecutor implements ClaudeInvoker {

    /** Enough to recognise an error near the start of a stream without reading a runaway log into memory. */
    private static final int DETECTION_READ_LIMIT = 256 * 1024;

    private final ClaudeConfig config;
    private final ClaudeProcessRunner processRunner;
    private final RemediationRunService runService;
    private final Clock clock;
    private final ClaudeResultExtractor resultExtractor = new ClaudeResultExtractor();

    public ClaudeCodeExecutor(
            ClaudeConfig config, ClaudeProcessRunner processRunner, RemediationRunService runService, Clock clock) {
        this.config = Objects.requireNonNull(config, "config");
        this.processRunner = Objects.requireNonNull(processRunner, "processRunner");
        this.runService = Objects.requireNonNull(runService, "runService");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public ClaudeRunOutcome run(ClaudeRunRequest request) {
        Objects.requireNonNull(request, "request");

        List<String> command = ClaudeCommand.build(
                config, request.toolPolicy(), request.maxTurns(), request.resumeSessionId());
        String startedAt = now();

        if (!Files.isDirectory(request.workspace())) {
            return workspaceMissing(request.workspace(), command, startedAt);
        }
        return execute(request.workspace(), request.prompt(), request.attemptDirectory(), command,
                request.timeout(), startedAt);
    }

    /** The mechanics, once there is a workspace and a prompt to run with. */
    private ClaudeRunOutcome execute(
            Path workspace,
            String prompt,
            Path attemptDirectory,
            List<String> command,
            Duration timeout,
            String startedAt) {

        Path promptFile = attemptDirectory.resolve(ClaudeArtifacts.PROMPT_FILE);
        Path stdoutFile = attemptDirectory.resolve(ClaudeArtifacts.STDOUT_FILE);
        Path stderrFile = attemptDirectory.resolve(ClaudeArtifacts.STDERR_FILE);

        runService.writeAttemptFile(promptFile, prompt);

        ClaudeInvocation invocation = processRunner.run(
                command, workspace, promptFile, stdoutFile, stderrFile, timeout);

        if (invocation.exitCode() != null) {
            runService.writeAttemptFile(
                    attemptDirectory.resolve(ClaudeArtifacts.EXIT_CODE_FILE), invocation.exitCode() + "\n");
        }

        boolean completedCleanly;
        String failureReason;
        if (!invocation.started()) {
            completedCleanly = false;
            failureReason = invocation.startFailure();
        } else if (invocation.timedOut()) {
            completedCleanly = false;
            failureReason = "Claude Code did not finish within " + timeout.toSeconds()
                    + "s and was stopped. Raise " + ClaudeConfig.CLAUDE_TIMEOUT_SECONDS + " if this "
                    + "library legitimately needs longer.";
        } else if (invocation.succeeded()) {
            completedCleanly = true;
            failureReason = null;
        } else {
            completedCleanly = false;
            failureReason = describeFailure(invocation, stdoutFile, stderrFile);
        }

        return new ClaudeRunOutcome(
                completedCleanly, invocation.exitCode(), invocation.timedOut(), failureReason,
                command, startedAt, now());
    }

    private ClaudeRunOutcome workspaceMissing(Path workspace, List<String> command, String startedAt) {
        return new ClaudeRunOutcome(false, null, false,
                "The workspace " + workspace + " does not exist, so there is nowhere to run.",
                command, startedAt, now());
    }

    /**
     * Names the likely cause of a non-zero exit. A rejected model gets its own message because that
     * is the one failure an operator could otherwise mistake for a bad upgrade attempt. Otherwise, if
     * Claude still wrote a structured result document despite the non-zero exit -- as it does for
     * {@code error_max_turns}, a turn budget exhausted before the model finished -- that subtype is
     * named explicitly, so an operator sees "ran out of turns" rather than only a bare exit code and
     * has to go find the reason in stdout.json themselves.
     */
    private String describeFailure(ClaudeInvocation invocation, Path stdoutFile, Path stderrFile) {
        String stdout = readCapped(stdoutFile);
        String stderr = readCapped(stderrFile);
        if (ModelAvailability.looksUnavailable(stdout, stderr)) {
            return ModelAvailability.unavailableMessage(config.model());
        }
        String subtype = resultExtractor.readSubtypeIfPresent(stdoutFile);
        String subtypeDetail = subtype == null ? "" : " (Claude reported subtype \"" + subtype + "\")";
        return "Claude Code exited with code " + invocation.exitCode() + subtypeDetail
                + ". See stdout.json and stderr.log in the attempt directory.";
    }

    private static String readCapped(Path path) {
        try {
            if (!Files.exists(path)) {
                return "";
            }
            byte[] bytes = Files.readAllBytes(path);
            int length = Math.min(bytes.length, DETECTION_READ_LIMIT);
            return new String(bytes, 0, length, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }

    private String now() {
        return DateTimeFormatter.ISO_INSTANT.format(clock.instant().truncatedTo(ChronoUnit.SECONDS));
    }
}
