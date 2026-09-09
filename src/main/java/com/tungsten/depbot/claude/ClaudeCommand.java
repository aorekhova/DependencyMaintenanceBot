package com.tungsten.depbot.claude;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Builds the exact argument list passed to Claude Code.
 *
 * <p>A pure function, kept separate from running anything, so the flags this application commits to
 * -- especially the ones that are safety controls -- can be asserted directly in a test without
 * starting a process.
 *
 * <p>What is permitted is not decided here: it comes in as a {@link ClaudeToolPolicy}, because the
 * assessment and implementation calls need different surfaces and both go through this one builder.
 *
 * <p><strong>Two omissions are deliberate.</strong> There is no
 * {@code --dangerously-skip-permissions}: the whole point of running an agent unattended against a
 * real repository is that the permission system stays on. And there is no fallback model argument;
 * see {@link ClaudeConfig}.
 *
 * <p>The prompt is <em>not</em> an argument. It is fed on standard input by
 * {@link ClaudeProcessRunner}, so a long task description can never run into a command-line length
 * limit and never needs quoting.
 */
public final class ClaudeCommand {

    private ClaudeCommand() {
    }

    /** The full command line under {@code policy}, using the configured turn limit. */
    public static List<String> build(ClaudeConfig config, ClaudeToolPolicy policy) {
        return build(config, policy, config.maxTurns());
    }

    /**
     * The full command line, executable first, ready to hand to a {@code ProcessBuilder}.
     *
     * @param maxTurns this invocation's turn limit, which a phase may need to differ from
     *                 {@link ClaudeConfig#maxTurns()}: investigating a repository and carrying out a
     *                 remediation in it are not the same amount of work
     */
    public static List<String> build(ClaudeConfig config, ClaudeToolPolicy policy, int maxTurns) {
        return build(config, policy, maxTurns, null);
    }

    /**
     * The full command line, with an optional {@code --resume}.
     *
     * @param resumeSessionId when not blank, continues the named session instead of starting a new
     *                         one -- used only by the assessment finalization call, so it can pick up
     *                         a conversation that ran out of turns with everything it had already
     *                         established still in context, rather than investigating from nothing
     */
    public static List<String> build(
            ClaudeConfig config, ClaudeToolPolicy policy, int maxTurns, String resumeSessionId) {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(policy, "policy");
        if (maxTurns <= 0) {
            throw new IllegalArgumentException("maxTurns must be greater than zero, but was: " + maxTurns);
        }

        List<String> command = new ArrayList<>();
        command.add(config.executable());
        // Non-interactive: read the prompt, do the work, exit -- never wait for a human.
        command.add("--print");
        command.add("--output-format");
        command.add("json");
        command.add("--model");
        command.add(config.model());
        command.add("--max-turns");
        command.add(Integer.toString(maxTurns));
        if (resumeSessionId != null && !resumeSessionId.isBlank()) {
            command.add("--resume");
            command.add(resumeSessionId);
        }
        command.add("--allowedTools");
        command.add(policy.allowedArgument());
        command.add("--disallowedTools");
        command.add(policy.disallowedArgument());
        return List.copyOf(command);
    }
}
