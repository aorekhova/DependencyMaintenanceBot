package com.tungsten.depbot.report.actionable;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Owns the on-disk lifecycle of the fixed report pair: invalidating the previous generation, then
 * publishing the new one.
 *
 * <h2>What is guaranteed</h2>
 * <ul>
 *   <li><strong>Invalidation is a hard gate.</strong> It runs before anything else in a scan. If it
 *       succeeds, neither report file exists, so absence reliably means the last scan did not
 *       succeed. If it fails the scan stops immediately, before Mend is contacted.</li>
 *   <li><strong>Temporaries are complete before publication starts.</strong> A partially written
 *       file is never a candidate for publication.</li>
 * </ul>
 *
 * <h2>What is best-effort</h2>
 * <p>Publishing two independent files cannot be made transactional by application code. Each move is
 * atomic on its own, but there is no cross-file commit. If the second publication fails, both
 * targets are removed so a mismatched generation cannot survive — and that removal is itself
 * best-effort, because the operating system, an antivirus scanner or a file-sync client can hold a
 * handle. Cleanup therefore continues past an individual failure, collects every one, and reports
 * through {@link ReportWriteException#pairStateGuaranteed()} whether the result is certain.
 *
 * <p>Rollback is <em>removal</em>, never restoration of the previous generation. Restoring would
 * reinstate exactly the stale files invalidation exists to eliminate.
 *
 * <p>Only the two fixed filenames and their own {@code .tmp} siblings are ever touched. Unrelated
 * files in the directory are left alone.
 */
public final class ReportWriter {

    /**
     * The move step, injectable so a test can make the <em>second</em> publication fail
     * deterministically. Reproducing that through the filesystem alone would depend on platform
     * behaviour and permissions, which makes for a flaky test of an important guarantee.
     *
     * <p>Public only so tests of the scan lifecycle, which live outside this package, can exercise
     * the mismatched-pair and blocked-cleanup paths. Production code uses {@link #ReportWriter()}.
     */
    @FunctionalInterface
    public interface FileMoveOperation {
        void move(Path source, Path target, CopyOption... options) throws IOException;
    }

    private final FileMoveOperation moveOperation;

    public ReportWriter() {
        this(Files::move);
    }

    /** See {@link FileMoveOperation}: a seam for testing publication failure. */
    public ReportWriter(FileMoveOperation moveOperation) {
        this.moveOperation = Objects.requireNonNull(moveOperation, "moveOperation");
    }

    /**
     * Removes the previous report pair, so a failed scan cannot leave a stale report looking current.
     *
     * <p>Deletes exactly the two target files and their own temporaries. A missing directory is a
     * silent success — there is nothing to invalidate.
     *
     * @throws ReportWriteException if any of those paths could not be removed, in which case the
     *                              scan must not proceed
     */
    public void invalidate(ReportDestination destination) {
        Objects.requireNonNull(destination, "destination");

        if (!Files.isDirectory(destination.directory())) {
            return;
        }

        Cleanup cleanup = removeQuietly(
                destination.jsonPath(),
                destination.markdownPath(),
                destination.jsonTempPath(),
                destination.markdownTempPath());

        if (!cleanup.unreconciled().isEmpty()) {
            throw failure("Could not remove the previous report files in "
                            + destination.directory()
                            + "; the current report state cannot be guaranteed.",
                    cleanup);
        }
    }

    /**
     * Writes both documents and publishes them as one coordinated pair.
     *
     * @throws ReportWriteException if either file could not be written or published
     */
    public WrittenReports publish(ReportDestination destination, String json, String markdown) {
        Objects.requireNonNull(destination, "destination");
        Objects.requireNonNull(json, "json");
        Objects.requireNonNull(markdown, "markdown");

        Path jsonTarget = destination.jsonPath();
        Path markdownTarget = destination.markdownPath();
        Path jsonTemp = destination.jsonTempPath();
        Path markdownTemp = destination.markdownTempPath();

        try {
            Files.createDirectories(destination.directory());
        } catch (IOException e) {
            throw new ReportWriteException(
                    "Could not create the report directory " + destination.directory(), e);
        }

        // Phase one: both temporaries written in full. Nothing is published yet, so a failure here
        // only needs the temporaries cleaned away.
        try {
            Files.writeString(jsonTemp, json, StandardCharsets.UTF_8);
            Files.writeString(markdownTemp, markdown, StandardCharsets.UTF_8);
        } catch (IOException e) {
            Cleanup cleanup = removeQuietly(jsonTemp, markdownTemp);
            throw failure("Could not write the temporary report files in "
                    + destination.directory(), cleanup, e);
        }

        // Phase two: commit both. A failure removes both targets so the two fixed filenames can
        // never represent different generations.
        try {
            publishOne(jsonTemp, jsonTarget);
            publishOne(markdownTemp, markdownTarget);
        } catch (IOException e) {
            Cleanup cleanup =
                    removeQuietly(jsonTarget, markdownTarget, jsonTemp, markdownTemp);
            throw failure("Could not publish the report pair in " + destination.directory()
                    + "; both report files were removed so they cannot disagree.", cleanup, e);
        }

        // Temporaries were moved away, but sweep in case a fallback left one behind.
        removeQuietly(jsonTemp, markdownTemp);
        return new WrittenReports(jsonTarget, markdownTarget);
    }

    private void publishOne(Path temp, Path target) throws IOException {
        try {
            moveOperation.move(temp, target,
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            // Some filesystems cannot move atomically. A non-atomic replace is still preferable to
            // failing outright, and the temporary was already written in full.
            moveOperation.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /**
     * Attempts to delete every path, continuing past individual failures so one blocked file cannot
     * prevent the others from being reconciled.
     */
    private static Cleanup removeQuietly(Path... paths) {
        List<Path> unreconciled = new ArrayList<>();
        List<IOException> failures = new ArrayList<>();

        for (Path path : paths) {
            try {
                Files.deleteIfExists(path);
            } catch (IOException e) {
                unreconciled.add(path);
                failures.add(e);
            }
        }
        return new Cleanup(List.copyOf(unreconciled), List.copyOf(failures));
    }

    private static ReportWriteException failure(String message, Cleanup cleanup) {
        return failure(message, cleanup, null);
    }

    private static ReportWriteException failure(String message, Cleanup cleanup, Throwable cause) {
        ReportWriteException thrown =
                new ReportWriteException(message, cleanup.unreconciled(), cause);
        // Attached rather than printed: they are for debugging, and the console must stay free of
        // stack traces.
        cleanup.failures().forEach(thrown::addSuppressed);
        return thrown;
    }

    /** The outcome of a best-effort deletion sweep. */
    private record Cleanup(List<Path> unreconciled, List<IOException> failures) {
    }
}
