package com.tungsten.depbot.claude;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Starts one Claude Code process and waits for it, with a hard timeout.
 *
 * <p>The command is passed to {@link ProcessBuilder} as a list of arguments. It is never assembled
 * into a single shell string: a library coordinate or a path containing a space, a quote or an
 * ampersand would otherwise change the meaning of the command, and on Windows there would be no
 * shell quoting rule that is safe for every case.
 *
 * <p><strong>All three streams are redirected to files rather than read from pipes.</strong> That
 * is not just convenient -- reading two pipes sequentially from one thread deadlocks as soon as the
 * unread one fills its OS buffer, and Claude Code is expected to produce plenty of both. Redirecting
 * makes the deadlock structurally impossible, and the files are exactly the attempt artifacts that
 * have to be kept anyway.
 */
public final class ClaudeProcessRunner {

    /**
     * @param workingDirectory the unit's worktree; Claude only ever runs inside it
     * @param promptFile       fed to the process on standard input
     */
    public ClaudeInvocation run(
            List<String> command,
            Path workingDirectory,
            Path promptFile,
            Path stdoutFile,
            Path stderrFile,
            Duration timeout) {

        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(workingDirectory.toFile());
        builder.redirectInput(promptFile.toFile());
        builder.redirectOutput(stdoutFile.toFile());
        builder.redirectError(stderrFile.toFile());

        Process process;
        try {
            process = builder.start();
        } catch (IOException e) {
            return ClaudeInvocation.failedToStart(
                    "Could not start \"" + command.get(0) + "\" in " + workingDirectory
                            + " (" + e.getMessage() + "). Is Claude Code installed and on PATH, "
                            + "or is " + ClaudeConfig.CLAUDE_EXECUTABLE + " pointing at the wrong file?");
        }

        boolean finished;
        try {
            finished = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            return ClaudeInvocation.failedToStart("Interrupted while waiting for " + command.get(0));
        }

        if (!finished) {
            killTree(process, promptFile, stdoutFile, stderrFile);
            return ClaudeInvocation.killedAfterTimeout();
        }

        return ClaudeInvocation.completed(process.exitValue());
    }

    /**
     * Kills the process <em>and everything it started</em>, and does not return until the redirected
     * files are actually free to delete.
     *
     * <p>{@link Process#destroyForcibly()} only ends the direct child. Anything that child spawned
     * -- a build, a test run, a package manager -- keeps running, and on Windows it also keeps
     * holding the redirected output files and the worktree directory open, so the next step cannot
     * clean up or even read what was written. Descendants are collected before the parent dies,
     * because once it is gone they are reparented and no longer reachable from this handle.
     *
     * <p>Waiting for {@code process.waitFor} and each descendant's {@code onExit} only proves the OS
     * scheduler has reaped the processes; it does not prove the handles those processes held on
     * {@code promptFile}, {@code stdoutFile} and {@code stderrFile} have actually been released. On
     * Windows, a real-time antivirus scan of the just-executed script routinely starts a few tens of
     * milliseconds <em>after</em> every process that touched these files has already exited, and
     * briefly holds them in a way that is long enough for a caller that immediately tries to delete
     * them to see a sharing violation. {@link #waitUntilReleased} is what closes that gap instead of
     * just hoping the timing works out.
     */
    private static void killTree(Process process, Path... redirectedFiles) {
        List<ProcessHandle> descendants = process.descendants().toList();
        process.destroyForcibly();
        descendants.forEach(ProcessHandle::destroyForcibly);

        try {
            process.waitFor(5, TimeUnit.SECONDS);
            for (ProcessHandle descendant : descendants) {
                descendant.onExit().get(5, TimeUnit.SECONDS);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
        } catch (ExecutionException | TimeoutException e) {
            // Best effort: a descendant that will not die is not worth failing the run over, and
            // the unit is already being reported as timed out.
        }

        for (Path file : redirectedFiles) {
            waitUntilReleased(file);
        }
    }

    private static final Duration RELEASE_WAIT_BUDGET = Duration.ofSeconds(2);
    private static final long RELEASE_POLL_INTERVAL_MILLIS = 20;
    private static final int CONSECUTIVE_SUCCESSES_REQUIRED = 15;

    /**
     * Waits, for a bounded total duration, until {@code file} is openable for writing and <em>stays</em>
     * that way for {@link #CONSECUTIVE_SUCCESSES_REQUIRED} consecutive checks.
     *
     * <p>A single successful check is not enough: measurement showed the file is openable
     * immediately after the process that held it dies (a plain probe-once-and-return always
     * succeeded on the first try), yet a moment later -- after this method had already returned --
     * deleting the very same file failed with a Windows sharing violation. That gap is a real-time
     * antivirus scan of the just-executed script and its directory that has not started yet at the
     * instant the process exits, so no probe taken immediately after exit can see it coming; only
     * staying open across a short window proves the scan is not about to start. Requiring
     * {@value #CONSECUTIVE_SUCCESSES_REQUIRED} consecutive successes, {@value
     * #RELEASE_POLL_INTERVAL_MILLIS}ms apart, means a scan that starts anywhere in that window
     * resets the streak and gets waited out, while a file that is never touched again returns almost
     * immediately. Still bounded by {@link #RELEASE_WAIT_BUDGET} overall, so a file that genuinely
     * never frees up cannot hang the run.
     */
    private static void waitUntilReleased(Path file) {
        long deadline = System.nanoTime() + RELEASE_WAIT_BUDGET.toNanos();
        int consecutiveSuccesses = 0;
        while (System.nanoTime() < deadline) {
            if (isReleased(file)) {
                consecutiveSuccesses++;
                if (consecutiveSuccesses >= CONSECUTIVE_SUCCESSES_REQUIRED) {
                    return;
                }
            } else {
                consecutiveSuccesses = 0;
            }
            try {
                Thread.sleep(RELEASE_POLL_INTERVAL_MILLIS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    /**
     * Whether {@code file} is currently free of any exclusive lock, checked by actually opening it
     * for writing -- the exact operation a lingering handle would block -- rather than merely
     * checking existence or permissions, neither of which reveals a sharing violation.
     */
    private static boolean isReleased(Path file) {
        if (!Files.exists(file)) {
            return true;
        }
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}
