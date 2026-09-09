package com.tungsten.depbot.diagnostics;

import com.tungsten.depbot.report.SecretRedactor;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Records an internal failure where a developer can read it, without putting anything on the console that
 * should not be there.
 *
 * <p>The console message for an unexpected error deliberately says nothing: the failure could have come
 * from anywhere, including code holding text authored by Mend or read out of a product repository. But a
 * message that says nothing and a failure that leaves no trace at all are different things, and the second
 * one made a real pilot failure impossible to diagnose -- the process printed one generic line, wrote no
 * artifacts, and the stack trace was simply gone.
 *
 * <p>What is recorded: the command that was running, the exception type, its message, and the full stack
 * trace including causes. What is <strong>not</strong> recorded: any environment variable value, any
 * credential, and any file content. Every line written passes through a {@link SecretRedactor} first, so a
 * message that happens to quote a credential is masked before it reaches the file rather than after.
 *
 * <p>Writing is best effort and never throws. This runs inside the last-resort error handler, and a
 * failure to record a failure must not replace it with a different one.
 */
public final class DiagnosticLog {

    /** Under the reports directory, so one place holds everything a run produces. */
    public static final String DEFAULT_DIRECTORY_NAME = "diagnostics";

    private static final DateTimeFormatter FILE_TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC);

    private final Path directory;
    private final Clock clock;
    private final SecretRedactor redactor;

    public DiagnosticLog(Path directory, Clock clock, SecretRedactor redactor) {
        this.directory = Objects.requireNonNull(directory, "directory");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.redactor = Objects.requireNonNull(redactor, "redactor");
    }

    /**
     * @param context what was being attempted, in terms safe to write down -- a command name and its
     *                arguments, never an environment value
     * @return where it was written, or {@code null} if it could not be written at all
     */
    public Path record(String context, Throwable failure) {
        Objects.requireNonNull(failure, "failure");
        try {
            Files.createDirectories(directory);
            Path file = directory.resolve(fileName());
            Files.writeString(file, content(context, failure), StandardCharsets.UTF_8);
            return file;
        } catch (IOException | RuntimeException e) {
            // Recording a failure must never become the failure. The console message is already out.
            return null;
        }
    }

    private String fileName() {
        String suffix = Long.toHexString(ThreadLocalRandom.current().nextLong() & 0xFFFFL);
        return "internal-error-" + FILE_TIMESTAMP.format(clock.instant()) + "-" + suffix + ".log";
    }

    private String content(String context, Throwable failure) {
        StringWriter stackTrace = new StringWriter();
        try (PrintWriter writer = new PrintWriter(stackTrace)) {
            failure.printStackTrace(writer);
        }

        String body = """
                Dependency Maintenance Bot -- internal error
                Recorded at: %s
                Context: %s
                Exception: %s
                Message: %s

                No environment variable values, credentials or file contents are recorded here, and every
                known credential is masked before writing.

                %s"""
                .formatted(
                        DateTimeFormatter.ISO_INSTANT.format(clock.instant().truncatedTo(ChronoUnit.SECONDS)),
                        context == null || context.isBlank() ? "not stated" : context,
                        failure.getClass().getName(),
                        failure.getMessage() == null ? "none" : failure.getMessage(),
                        stackTrace);

        return redactor.redact(body);
    }
}
