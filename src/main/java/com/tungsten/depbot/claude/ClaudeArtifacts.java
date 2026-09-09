package com.tungsten.depbot.claude;

/**
 * The fixed filenames one Claude invocation leaves behind in its attempt directory.
 *
 * <p>Named here rather than spelled out at each use so a service that needs to read back what
 * Claude printed -- {@code BatchAnalysisService} parsing its own call's {@code stdout.json},
 * for instance -- refers to the same constant the invoker wrote, instead of repeating a string
 * literal that could drift.
 */
public final class ClaudeArtifacts {

    /** The exact prompt fed to the process on standard input. */
    public static final String PROMPT_FILE = "prompt.md";

    /** Claude Code's {@code --output-format json} document. */
    public static final String STDOUT_FILE = "stdout.json";

    public static final String STDERR_FILE = "stderr.log";

    /** Absent when the process timed out or never started, since neither produces an exit code. */
    public static final String EXIT_CODE_FILE = "exit-code.txt";

    private ClaudeArtifacts() {
    }
}
