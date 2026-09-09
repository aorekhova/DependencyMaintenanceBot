package com.tungsten.depbot.cli;

import com.tungsten.depbot.run.RunManifest;

/**
 * What {@link PrepareRemediationBranchesCommand#runAndReport()} produced: an exit code, and the
 * manifest it wrote -- or {@code null} if the stage failed before a manifest could exist.
 *
 * <p>{@code manifest} lets {@code RemediateCommand} chain straight into execution without
 * re-reading the manifest back off disk.
 */
public record BranchPreparationStageResult(ExitCode exitCode, RunManifest manifest) {

    public boolean succeeded() {
        return exitCode == ExitCode.SUCCESS;
    }
}
