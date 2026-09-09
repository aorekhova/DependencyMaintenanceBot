package com.tungsten.depbot.validation;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * Runs one Maven goal in a project directory and captures what it said.
 *
 * <p>Separate from the gate's own judgement for the same reason {@code ClaudeProcessRunner} is separate
 * from {@code ClaudeCodeExecutor}: starting a process, bounding it and reading its output is mechanical,
 * and what the output <em>means</em> is not.
 *
 * <p>Prefers the project's own Maven Wrapper when it has one. A project pinned to a wrapper version is
 * pinned for a reason, and validating with whatever {@code mvn} happens to be on {@code PATH} could
 * resolve differently from the build that will actually run.
 */
public final class MavenInvocation {

    /** Combined output is read into memory; enough to diagnose a failure without holding a runaway log. */
    private static final int OUTPUT_LIMIT = 256 * 1024;

    private static final boolean WINDOWS =
            System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win");

    private MavenInvocation() {
    }

    /** The Maven executable to use for {@code projectDirectory}: its wrapper if present, otherwise {@code mvn}. */
    public static String executableFor(Path projectDirectory) {
        if (WINDOWS && Files.isRegularFile(projectDirectory.resolve("mvnw.cmd"))) {
            return projectDirectory.resolve("mvnw.cmd").toString();
        }
        if (!WINDOWS && Files.isRegularFile(projectDirectory.resolve("mvnw"))) {
            return projectDirectory.resolve("mvnw").toString();
        }
        return WINDOWS ? "mvn.cmd" : "mvn";
    }

    /**
     * @return the process result, or {@link Result#failedToStart} / {@link Result#timedOut} -- never an
     *         exception for an ordinary failure, since being unable to run Maven is something the gate has
     *         to report rather than something the caller can fix
     */
    public static Result run(Path projectDirectory, List<String> command, Duration timeout) {
        // heartbeatInterval == timeout: the poll loop below waits once for the full timeout and can
        // never call the heartbeat, which is exactly the single-wait behavior this method has always had.
        return run(projectDirectory, command, timeout, timeout, () -> { });
    }

    /**
     * As {@link #run(Path, List, Duration)}, but polls in slices of {@code heartbeatInterval} instead of
     * waiting once for the whole timeout, calling {@code onHeartbeat} between polls while the process is
     * still running. Exists for a gate whose run can last long enough that "still working" and "hung"
     * would otherwise look identical from the outside.
     *
     * @param onHeartbeat called with no result guarantee about how many times, if any -- zero for a
     *                    process that finishes inside the first interval. Wrapped in its own
     *                    exception guard: a heartbeat must never be able to abort a real build.
     */
    public static Result run(
            Path projectDirectory, List<String> command, Duration timeout,
            Duration heartbeatInterval, Runnable onHeartbeat) {

        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(projectDirectory.toFile());
        builder.redirectErrorStream(true);

        Process process;
        try {
            process = builder.start();
        } catch (IOException e) {
            return Result.failedToStart(
                    "Could not start \"" + command.get(0) + "\" in " + projectDirectory + " ("
                            + e.getMessage() + ").");
        }

        StringBuilder output = new StringBuilder();
        Thread reader = new Thread(() -> {
            // Read on its own thread: with a bounded wait on the process, reading inline would block
            // forever on a process that neither finishes nor closes its output.
            try (InputStream in = process.getInputStream()) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) >= 0) {
                    if (output.length() < OUTPUT_LIMIT) {
                        output.append(new String(buffer, 0, read, StandardCharsets.UTF_8));
                    }
                }
            } catch (IOException e) {
                // The process was killed mid-read; whatever was captured is still worth keeping.
            }
        });
        reader.setDaemon(true);
        reader.start();

        boolean finished;
        try {
            finished = pollUntilFinishedOrTimedOut(process, timeout, heartbeatInterval, onHeartbeat);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            killTree(process);
            return Result.timedOut("Interrupted while waiting for " + command.get(0) + ".",
                    output.toString());
        }

        if (!finished) {
            killTree(process);
            return Result.timedOut(
                    command.get(0) + " did not finish within " + timeout.toSeconds() + "s and was stopped.",
                    output.toString());
        }

        try {
            reader.join(TimeUnit.SECONDS.toMillis(5));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return new Result(true, process.exitValue(), output.toString(), null);
    }

    /**
     * Waits for {@code process}, in slices no longer than {@code heartbeatInterval}, firing
     * {@code onHeartbeat} between slices for as long as time remains and the process has not finished.
     *
     * <p>With {@code heartbeatInterval == timeout} (the plain 3-arg {@link #run}'s case) this performs
     * exactly one poll of the full timeout duration and never reaches the heartbeat call, which is what
     * makes that overload's behavior provably identical to a single {@code waitFor(timeout, ...)}.
     */
    private static boolean pollUntilFinishedOrTimedOut(
            Process process, Duration timeout, Duration heartbeatInterval, Runnable onHeartbeat)
            throws InterruptedException {

        long deadlineNanos = System.nanoTime() + timeout.toNanos();
        while (true) {
            long remainingNanos = deadlineNanos - System.nanoTime();
            if (remainingNanos <= 0) {
                return false;
            }
            long waitNanos = Math.min(remainingNanos, heartbeatInterval.toNanos());
            if (process.waitFor(waitNanos, TimeUnit.NANOSECONDS)) {
                return true;
            }
            if (deadlineNanos - System.nanoTime() > 0) {
                try {
                    onHeartbeat.run();
                } catch (RuntimeException e) {
                    // A heartbeat callback (console printing, progress bookkeeping) must never be able
                    // to abort a real, possibly long-running build.
                }
            }
        }
    }

    /**
     * Maven starts a JVM and may start more; killing only the direct child leaves those holding the
     * project directory open, which on Windows blocks the very files the next step has to read.
     */
    private static void killTree(Process process) {
        List<ProcessHandle> descendants = new ArrayList<>(process.descendants().toList());
        process.destroyForcibly();
        descendants.forEach(ProcessHandle::destroyForcibly);
        try {
            process.waitFor(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * {@code started} false means the executable could not be launched; {@code exitCode} is {@code null}
     * when the process produced none, which covers both that case and a forced kill after the timeout.
     */
    public record Result(boolean started, Integer exitCode, String output, String failureMessage) {

        public static Result failedToStart(String message) {
            return new Result(false, null, "", message);
        }

        public static Result timedOut(String message, String output) {
            return new Result(true, null, output, message);
        }

        public boolean succeeded() {
            return started && exitCode != null && exitCode == 0;
        }
    }
}
