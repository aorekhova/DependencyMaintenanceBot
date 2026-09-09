package com.tungsten.depbot.run;

import com.tungsten.depbot.git.RemediationBranchOutcome;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

/**
 * Records a completed branch-preparation run: writes {@code <runsRoot>/<runId>/run-manifest.json}
 * and one task file per unit under {@code <runsRoot>/<runId>/tasks/}.
 *
 * <p>{@code runsRoot} is injected (production wiring points it at {@code reports/runs}) rather
 * than hardcoded, the same reason {@code ReportDestination} takes a directory instead of assuming
 * one: tests must never be able to write outside their own temporary directory.
 *
 * <p>Every run gets its own uniquely-named subdirectory (the run id already guarantees this), so
 * unlike the scan report or the remediation plan there is nothing to invalidate first -- a new run
 * can never collide with or overwrite a previous one's files.
 */
public final class RemediationRunService {

    private final Clock clock;
    private final Path runsRoot;
    private final RunManifestJsonRenderer manifestRenderer = new RunManifestJsonRenderer();
    private final RemediationUnitTaskRenderer taskRenderer = new RemediationUnitTaskRenderer();

    public RemediationRunService(Clock clock, Path runsRoot) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.runsRoot = Objects.requireNonNull(runsRoot, "runsRoot");
    }

    /** Where {@link #recordRun} will write the manifest for a given run id, without writing anything. */
    public Path manifestPathFor(String runId) {
        return RunPaths.manifestPath(runsRoot, runId);
    }

    /** Where one attempt's artifacts belong. Creates nothing; the caller decides when to write. */
    public Path attemptDirectoryFor(String runId, String unitId, int attemptNumber) {
        return RunPaths.attemptDirectory(runsRoot, runId, unitId, attemptNumber);
    }

    /**
     * One unit's directory, for a caller that arranges its own subdirectories inside it -- a phase's
     * artifacts, for instance.
     *
     * <p>Deliberately returns the directory rather than taking a phase: this package has no reason to
     * know how many phases there are or what they are called, and having it depend on the package that
     * runs Claude -- which already depends on this one -- would only buy a circular one.
     */
    public Path unitDirectoryFor(String runId, String unitId) {
        return RunPaths.unitDirectory(runsRoot, runId, unitId);
    }

    /**
     * Rewrites the manifest in place, so the file on disk tracks the run as it progresses rather
     * than only recording its final state.
     *
     * @throws RunManifestWriteException if it could not be written
     */
    public void writeManifest(RunManifest manifest) {
        Objects.requireNonNull(manifest, "manifest");
        write(manifestPathFor(manifest.runId()), manifestRenderer.render(manifest));
    }

    /** Writes one attempt artifact, creating the attempt directory if needed. */
    public void writeAttemptFile(Path path, String content) {
        write(path, content);
    }

    /** Writes one run-level artifact -- the summary that indexes a whole run, rather than one attempt. */
    public void writeRunArtifact(Path path, String content) {
        write(path, content);
    }

    /** Where everything about one run lives. Creates nothing. */
    public Path runDirectoryFor(String runId) {
        return RunPaths.runDirectory(runsRoot, runId);
    }

    /**
     * @param workspacePath the single managed checkout every unit in this run will work in
     * @throws RunManifestWriteException if the manifest or any task file could not be written
     */
    public RunManifest recordRun(RemediationBranchOutcome outcome, String workspacePath) {
        Objects.requireNonNull(outcome, "outcome");
        Objects.requireNonNull(outcome.runId(), "outcome.runId");
        Objects.requireNonNull(workspacePath, "workspacePath");

        RunManifest manifest = RunManifestBuilder.build(
                runsRoot, outcome.runId(), generatedAt(), outcome.baseCommitSha(), outcome.plan(),
                outcome.created(), workspacePath);

        writeManifest(manifest);
        for (RemediationUnit unit : manifest.units()) {
            writeTask(unit);
        }
        return manifest;
    }

    private void writeTask(RemediationUnit unit) {
        write(Path.of(unit.taskFile()), taskRenderer.render(unit));
    }

    private static void write(Path path, String content) {
        try {
            Files.createDirectories(path.getParent());
            Files.writeString(path, content, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RunManifestWriteException("Could not write " + path, e);
        }
    }

    private String generatedAt() {
        return DateTimeFormatter.ISO_INSTANT.format(clock.instant().truncatedTo(ChronoUnit.SECONDS));
    }
}
