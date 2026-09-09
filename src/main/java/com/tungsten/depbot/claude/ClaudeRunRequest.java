package com.tungsten.depbot.claude;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;

/**
 * One fully-specified Claude Code invocation: which phase it is, where it runs, what it is asked,
 * where its artifacts go, and the limits it runs under.
 *
 * <p>This is what keeps a single invoker serving both phases. Everything that differs between an
 * assessment and an implementation is data on this record; nothing about either phase is known to
 * {@link ClaudeCodeExecutor} or {@link ClaudeProcessRunner}.
 *
 * <p>{@code prompt} is the complete prompt text, already rendered. The invoker writes it verbatim --
 * it never appends, wraps or edits instructions of its own, so what a phase's service composed is
 * exactly what Claude reads and exactly what {@code prompt.md} preserves.
 *
 * <p>{@code resumeSessionId} is {@code null} for every ordinary call. It is set only for the assessment
 * finalization request, which continues a session that ran out of turns or time instead of starting a
 * fresh one -- so whatever that session had already established is still in context, and the
 * finalization call only has to write it down, not rediscover it.
 */
public record ClaudeRunRequest(
        ClaudePhase phase,
        Path workspace,
        String prompt,
        Path attemptDirectory,
        ClaudeToolPolicy toolPolicy,
        int maxTurns,
        Duration timeout,
        String resumeSessionId) {

    public ClaudeRunRequest {
        Objects.requireNonNull(phase, "phase");
        Objects.requireNonNull(workspace, "workspace");
        Objects.requireNonNull(prompt, "prompt");
        Objects.requireNonNull(attemptDirectory, "attemptDirectory");
        Objects.requireNonNull(toolPolicy, "toolPolicy");
        Objects.requireNonNull(timeout, "timeout");
        if (prompt.isBlank()) {
            throw new IllegalArgumentException("prompt must not be blank");
        }
        if (maxTurns <= 0) {
            throw new IllegalArgumentException("maxTurns must be greater than zero, but was: " + maxTurns);
        }
        if (timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("timeout must be positive, but was: " + timeout);
        }
    }

    /** A request with no session to resume -- every ordinary call, for either phase. */
    public ClaudeRunRequest(
            ClaudePhase phase, Path workspace, String prompt, Path attemptDirectory,
            ClaudeToolPolicy toolPolicy, int maxTurns, Duration timeout) {
        this(phase, workspace, prompt, attemptDirectory, toolPolicy, maxTurns, timeout, null);
    }

    /**
     * A request using {@code phase}'s own tool policy and the configured turn and time limits -- the
     * ordinary case, where a phase has no reason to deviate from the operator's configuration.
     */
    public static ClaudeRunRequest of(
            ClaudePhase phase, Path workspace, String prompt, Path attemptDirectory, ClaudeConfig config) {
        Objects.requireNonNull(config, "config");
        return new ClaudeRunRequest(
                phase,
                workspace,
                prompt,
                attemptDirectory,
                ClaudeToolPolicy.forPhase(phase),
                config.maxTurnsFor(phase),
                config.timeoutFor(phase));
    }

    /**
     * The short, tool-free, bounded request for "write down the final document, do not investigate
     * further": {@link ClaudeToolPolicy#forAssessmentFinalization()}, its own small turn budget, and --
     * when {@code resumeSessionId} is known -- a resume of that same session rather than a fresh one.
     * Used for two distinct situations that share the exact same shape: an assessment which ran out of
     * turns or time (the original use), and one whose document completed substantively but could not be
     * parsed or validated -- a bounded, one-shot schema-repair call (see
     * {@code BatchAnalysisService#runSchemaRepairAttempt}). Neither is a second investigation; both ask
     * for the same thing, a corrected final document from what is already known.
     */
    public static ClaudeRunRequest ofAssessmentFinalization(
            Path workspace, String prompt, Path attemptDirectory, ClaudeConfig config, String resumeSessionId) {
        Objects.requireNonNull(config, "config");
        return new ClaudeRunRequest(
                ClaudePhase.ASSESSMENT,
                workspace,
                prompt,
                attemptDirectory,
                ClaudeToolPolicy.forAssessmentFinalization(),
                config.analysisFinalizationMaxTurns(),
                config.timeout(),
                resumeSessionId);
    }

    /**
     * The second Vulnerability Analysis attempt, run only when the first ran out of turns or time --
     * the <em>same</em> tool policy as an ordinary analysis call ({@link ClaudeToolPolicy#forPhase},
     * still a full, free investigation, not a report-only write-up), a smaller turn and time budget, and
     * -- when {@code resumeSessionId} is known -- a resume of that same session rather than a fresh one,
     * so whatever the first attempt had already established stays in context instead of being thrown
     * away and re-derived.
     */
    public static ClaudeRunRequest ofAssessmentSecondAttempt(
            Path workspace, String prompt, Path attemptDirectory, ClaudeConfig config, String resumeSessionId) {
        Objects.requireNonNull(config, "config");
        return new ClaudeRunRequest(
                ClaudePhase.ASSESSMENT,
                workspace,
                prompt,
                attemptDirectory,
                ClaudeToolPolicy.forPhase(ClaudePhase.ASSESSMENT),
                config.analysisSecondAttemptMaxTurns(),
                config.analysisSecondAttemptTimeout(),
                resumeSessionId);
    }

    /**
     * The short, read-only finalization request that follows an implementation which ran out of turns
     * or time: {@link ClaudeToolPolicy#forImplementationFinalization()}, its own small turn budget, and
     * -- when {@code resumeSessionId} is known -- a resume of that same session rather than a fresh one.
     */
    public static ClaudeRunRequest ofImplementationFinalization(
            Path workspace, String prompt, Path attemptDirectory, ClaudeConfig config, String resumeSessionId) {
        Objects.requireNonNull(config, "config");
        return new ClaudeRunRequest(
                ClaudePhase.IMPLEMENTATION,
                workspace,
                prompt,
                attemptDirectory,
                ClaudeToolPolicy.forImplementationFinalization(),
                config.implementationFinalizationMaxTurns(),
                config.timeout(),
                resumeSessionId);
    }

    /**
     * The short, tool-free finalization request that follows a Human Review Engineer call which ran out
     * of turns or time: {@link ClaudeToolPolicy#forHumanReviewFinalization()}, its own small turn budget,
     * and -- when {@code resumeSessionId} is known -- a resume of that same session rather than a fresh
     * one.
     */
    public static ClaudeRunRequest ofHumanReviewFinalization(
            Path workspace, String prompt, Path attemptDirectory, ClaudeConfig config, String resumeSessionId) {
        Objects.requireNonNull(config, "config");
        return new ClaudeRunRequest(
                ClaudePhase.HUMAN_REVIEW,
                workspace,
                prompt,
                attemptDirectory,
                ClaudeToolPolicy.forHumanReviewFinalization(),
                config.humanReviewFinalizationMaxTurns(),
                config.timeout(),
                resumeSessionId);
    }

    /** Where this invocation's Claude Code JSON output will be written. */
    public Path stdoutFile() {
        return attemptDirectory.resolve(ClaudeArtifacts.STDOUT_FILE);
    }
}
