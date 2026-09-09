package com.tungsten.depbot.run;

import com.tungsten.depbot.remediation.LibraryRemediation;

import java.util.List;

/**
 * Everything recorded about one {@code create-remediation-worktrees} (or {@code remediate}) run:
 * one {@link RemediationUnit} per library that got a branch and worktree, plus the libraries the
 * plan could not classify into a severity bucket.
 *
 * <p>{@code manualAnalysisRequired} is carried through unchanged from the plan -- these libraries
 * are recorded for visibility only. They never become units, never get a branch or worktree, and
 * never get a task file: a human decision is needed before there is anything to automate.
 *
 * <p>{@code model} is {@code null} until an executor actually runs the units, and is then the exact
 * model every attempt in this run used. Recording it here means a finished run always states which
 * model produced its changes, rather than leaving that to be inferred from whatever the environment
 * happens to hold later.
 *
 * <p>The manifest is rewritten as the run progresses, so the file on disk always reflects the
 * current state of every unit rather than only the state at the end.
 */
public record RunManifest(
        String runId,
        String generatedAt,
        String manifestVersion,
        String baseCommitSha,
        String model,
        List<RemediationUnit> units,
        List<LibraryRemediation> manualAnalysisRequired,
        String sourceSnapshotFingerprint) {

    public static final String CURRENT_VERSION = "1.0";

    public RunManifest {
        manifestVersion = (manifestVersion == null || manifestVersion.isBlank()) ? CURRENT_VERSION : manifestVersion;
        units = units == null ? List.of() : List.copyOf(units);
        manualAnalysisRequired = manualAnalysisRequired == null ? List.of() : List.copyOf(manualAnalysisRequired);
    }

    /**
     * Legacy 7-arg constructor kept for every existing caller: {@code sourceSnapshotFingerprint}
     * defaults to {@code null}, exactly as an old persisted manifest (predating the Mend snapshot
     * history store) reads back today.
     */
    public RunManifest(
            String runId,
            String generatedAt,
            String manifestVersion,
            String baseCommitSha,
            String model,
            List<RemediationUnit> units,
            List<LibraryRemediation> manualAnalysisRequired) {
        this(runId, generatedAt, manifestVersion, baseCommitSha, model, units, manualAnalysisRequired, null);
    }

    /** Returns a copy recording the model used and the current state of every unit. */
    public RunManifest withExecution(String executionModel, List<RemediationUnit> updatedUnits) {
        return new RunManifest(runId, generatedAt, manifestVersion, baseCommitSha, executionModel,
                updatedUnits, manualAnalysisRequired, sourceSnapshotFingerprint);
    }
}
