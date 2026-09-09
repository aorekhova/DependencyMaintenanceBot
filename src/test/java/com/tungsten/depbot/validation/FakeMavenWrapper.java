package com.tungsten.depbot.validation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

/**
 * Writes a {@code mvnw} into a project directory that prints canned output and exits with a chosen code.
 *
 * <p>Exists so the gate's three verdicts can be exercised deterministically, on any machine, without a warm
 * local repository or a real multi-module project -- and against the real {@link ProcessBuilder} path, since
 * the argument list and the working directory are exactly what a real invocation would use.
 *
 * <p>The gate prefers a project's own wrapper, which is what makes this work at all: dropping a wrapper into
 * the temporary project is enough to take over the invocation.
 *
 * <p>Public so other packages' tests (for example the CLI-level pilot tests, which need to keep a real
 * {@link MavenBuildValidationGate} from ever reaching a real network) can reuse the same fixture rather
 * than hand-rolling one -- the same reason {@code GitTestRepos}/{@code Implementations} are public.
 * Test-support code only; never shipped in the production jar.
 */
public final class FakeMavenWrapper {

    private static final boolean WINDOWS =
            System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win");

    private FakeMavenWrapper() {
    }

    /** Writes the wrapper and returns the file it recorded its arguments into. */
    public static Path writeInto(Path projectDirectory, String output, int exitCode) throws IOException {
        Files.createDirectories(projectDirectory);
        Path argsFile = projectDirectory.resolve("recorded-maven-args.txt");
        Path outputFile = projectDirectory.resolve("canned-maven-output.txt");
        Files.writeString(outputFile, output, StandardCharsets.UTF_8);

        if (WINDOWS) {
            Path script = projectDirectory.resolve("mvnw.cmd");
            Files.writeString(script, "@echo off\r\n"
                    + "echo %* > \"" + argsFile + "\"\r\n"
                    + "type \"" + outputFile + "\"\r\n"
                    + "exit /b " + exitCode + "\r\n", StandardCharsets.UTF_8);
        } else {
            Path script = projectDirectory.resolve("mvnw");
            Files.writeString(script, "#!/bin/sh\n"
                    + "printf '%s\\n' \"$*\" > '" + argsFile + "'\n"
                    + "cat '" + outputFile + "'\n"
                    + "exit " + exitCode + "\n", StandardCharsets.UTF_8);
            script.toFile().setExecutable(true);
        }
        return argsFile;
    }

    /** A wrapper that hangs for {@code seconds}, so the timeout path can be exercised. */
    public static void writeSlowWrapperInto(Path projectDirectory, int seconds) throws IOException {
        Files.createDirectories(projectDirectory);
        if (WINDOWS) {
            // ping, not timeout: timeout needs a console and fails when stdin is redirected.
            Files.writeString(projectDirectory.resolve("mvnw.cmd"),
                    "@echo off\r\nping -n " + (seconds + 1) + " 127.0.0.1 > nul 2>&1\r\nexit /b 0\r\n",
                    StandardCharsets.UTF_8);
        } else {
            Path script = projectDirectory.resolve("mvnw");
            Files.writeString(script, "#!/bin/sh\nsleep " + seconds + "\nexit 0\n", StandardCharsets.UTF_8);
            script.toFile().setExecutable(true);
        }
    }
}
