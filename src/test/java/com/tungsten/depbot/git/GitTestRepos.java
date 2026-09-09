package com.tungsten.depbot.git;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Sets up real, temporary git repositories for tests. Nothing about git is faked: these tests
 * exercise {@link GitCommandRunner} and its callers against an actual {@code git} executable, the
 * same way the real {@code create-remediation-worktrees} command does.
 *
 * <p>Public (rather than package-private) purely so the {@code cli} package's
 * {@code RemediateCommandTest} can reuse the same real-repo setup for its own end-to-end test --
 * this is test-support code, never shipped in the production jar.
 */
public final class GitTestRepos {

    private GitTestRepos() {
    }

    /**
     * Creates a bare "origin" repository and a clone of it with one commit pushed to
     * {@code master}, both under {@code tempDir}. Returns the path to the clone.
     */
    public static Path createOriginAndClone(Path tempDir) throws IOException, InterruptedException {
        Path origin = tempDir.resolve("origin.git");
        Path work = tempDir.resolve("work");

        run(tempDir, "git", "init", "-q", "--bare", origin.toString());
        run(tempDir, "git", "clone", "-q", origin.toString(), work.toString());
        run(work, "git", "config", "user.email", "test@example.com");
        run(work, "git", "config", "user.name", "test");
        // Independent of whatever core.autocrlf the host's global git config has: without this, a
        // Windows git install can rewrite "hello\n" to "hello\r\n" on checkout, making file content
        // assertions fail for reasons that have nothing to do with the code under test.
        run(work, "git", "config", "core.autocrlf", "false");
        Files.writeString(work.resolve("file.txt"), "hello\n", StandardCharsets.UTF_8);
        run(work, "git", "add", "file.txt");
        run(work, "git", "commit", "-q", "-m", "init");
        run(work, "git", "push", "-q", "origin", "HEAD:master");

        return work;
    }

    /**
     * Creates an origin holding {@code master} plus one commit on each of {@code extraBranches}, then a
     * <strong>single-branch</strong> clone of {@code master}.
     *
     * <p>Single-branch on purpose. It leaves {@code remote.origin.fetch} pointing at one branch, which is
     * exactly the situation an explicit refspec exists to defeat: a plain {@code git fetch} in such a
     * clone brings back only {@code master}, so a release or hotfix branch an assessment needs to find is
     * simply not there to be found. Tests that assert the refresh works must start from a clone where it
     * measurably has something to do.
     *
     * @return the path to the clone
     */
    public static Path createOriginAndSingleBranchClone(Path tempDir, String... extraBranches)
            throws IOException, InterruptedException {
        Path origin = tempDir.resolve("origin.git");
        Path seed = tempDir.resolve("seed");
        Path work = tempDir.resolve("work");

        run(tempDir, "git", "init", "-q", "--bare", origin.toString());
        // -c core.autocrlf=false on the clone itself, not just afterwards: the conversion happens while
        // the working tree is being written out, so a host with autocrlf=true would leave every file
        // differing from the index and the clone dirty before any test had touched it.
        run(tempDir, "git", "-c", "core.autocrlf=false", "clone", "-q",
                origin.toString(), seed.toString());
        configure(seed);
        commitFile(seed, "file.txt", "hello\n", "init");
        run(seed, "git", "push", "-q", "origin", "HEAD:master");

        for (String branch : extraBranches) {
            run(seed, "git", "checkout", "-q", "-b", branch);
            commitFile(seed, "file.txt", "on " + branch + "\n", "work on " + branch);
            run(seed, "git", "push", "-q", "origin", "HEAD:refs/heads/" + branch);
            run(seed, "git", "checkout", "-q", "master");
        }

        run(tempDir, "git", "-c", "core.autocrlf=false", "clone", "-q", "--single-branch",
                "--branch", "master", origin.toString(), work.toString());
        configure(work);
        if (!readOutput(work, "git", "status", "--porcelain").isBlank()) {
            throw new AssertionError(
                    "the fixture clone is not clean, so no test starting from it can be trusted");
        }
        return work;
    }

    /** The commit a ref is at in {@code repo}, asked of git directly. */
    public static String shaOf(Path repo, String ref) throws IOException, InterruptedException {
        return readOutput(repo, "git", "rev-parse", "--verify", ref + "^{commit}").strip();
    }

    public static String currentBranch(Path repo) throws IOException, InterruptedException {
        return readOutput(repo, "git", "rev-parse", "--abbrev-ref", "HEAD").strip();
    }

    private static void configure(Path repo) throws IOException, InterruptedException {
        run(repo, "git", "config", "user.email", "test@example.com");
        run(repo, "git", "config", "user.name", "test");
        run(repo, "git", "config", "core.autocrlf", "false");
    }

    private static void commitFile(Path repo, String name, String content, String message)
            throws IOException, InterruptedException {
        Files.writeString(repo.resolve(name), content, StandardCharsets.UTF_8);
        run(repo, "git", "add", name);
        run(repo, "git", "commit", "-q", "-m", message);
    }

    public static void run(Path directory, String... command) throws IOException, InterruptedException {
        readOutput(directory, command);
    }

    public static String readOutput(Path directory, String... command) throws IOException, InterruptedException {
        Process process = new ProcessBuilder(command)
                .directory(directory.toFile())
                .redirectErrorStream(true)
                .start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new AssertionError("Test setup command failed: " + String.join(" ", command) + "\n" + output);
        }
        return output;
    }
}
