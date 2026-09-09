package com.tungsten.depbot.report.actionable;

import java.nio.file.Path;
import java.util.List;

/**
 * A report file could not be invalidated or published.
 *
 * <p>Carries whether the on-disk state of the report pair is still known. Publishing two independent
 * files cannot be made transactional by application code: if the second file fails to publish, the
 * writer removes both targets so no mismatched generation survives — but that removal can itself be
 * blocked by the operating system, an antivirus scanner, or a file-sync client holding a handle.
 *
 * <p>When cleanup succeeded, {@link #pairStateGuaranteed()} is {@code true} and no report files
 * remain. When it did not, the paths that could not be reconciled are listed so the operator knows
 * exactly what to inspect, and the individual failures are attached as suppressed exceptions for
 * debugging rather than printed.
 *
 * <p>Messages name paths only. They never contain report content.
 */
public class ReportWriteException extends RuntimeException {

    private final List<Path> unreconciledPaths;

    public ReportWriteException(String safeMessage, List<Path> unreconciledPaths, Throwable cause) {
        super(safeMessage, cause);
        this.unreconciledPaths =
                unreconciledPaths == null ? List.of() : List.copyOf(unreconciledPaths);
    }

    public ReportWriteException(String safeMessage, Throwable cause) {
        this(safeMessage, List.of(), cause);
    }

    /**
     * True when the report pair is in a known state — every file that needed removing was removed.
     * False when cleanup was itself blocked and the directory may hold a partial or mismatched pair.
     */
    public boolean pairStateGuaranteed() {
        return unreconciledPaths.isEmpty();
    }

    /** Paths that could not be reconciled. Safe to display. */
    public List<Path> unreconciledPaths() {
        return unreconciledPaths;
    }
}
