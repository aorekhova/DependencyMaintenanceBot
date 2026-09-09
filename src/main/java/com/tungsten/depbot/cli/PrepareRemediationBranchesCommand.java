package com.tungsten.depbot.cli;

import com.tungsten.depbot.config.ConfigurationException;
import com.tungsten.depbot.git.CreatedBranch;
import com.tungsten.depbot.git.GitCommandException;
import com.tungsten.depbot.git.GitWorktreeConfig;
import com.tungsten.depbot.git.GroupFailure;
import com.tungsten.depbot.git.RemediationBranchOutcome;
import com.tungsten.depbot.git.RemediationBranchPreparationService;
import com.tungsten.depbot.remediation.DependencyCoordinates;
import com.tungsten.depbot.remediation.DependencyNotFoundException;
import com.tungsten.depbot.remediation.RemediationSourceException;
import com.tungsten.depbot.report.ConsoleReporter;
import com.tungsten.depbot.run.RemediationRunService;
import com.tungsten.depbot.run.RunManifest;
import com.tungsten.depbot.run.RunManifestWriteException;

import java.util.Objects;
import java.util.function.Supplier;

/**
 * Runs the {@code prepare-remediation-branches} command (also {@code create-remediation-worktrees},
 * kept as a deprecated alias for the same thing): create one branch per non-empty severity, all
 * from the same {@code origin/master} commit, and record the run's manifest and task files.
 *
 * <p>Never checks anything out and never creates a worktree -- see
 * {@link RemediationBranchPreparationService}. That is what makes this exact same command safe to
 * reuse, unmodified, as {@code remediate}'s first git-touching stage: preparing branches can never
 * itself leave the checkout somewhere unexpected.
 */
public final class PrepareRemediationBranchesCommand {

    private final RemediationBranchPreparationService branchService;
    private final Supplier<GitWorktreeConfig> configSource;
    private final RemediationRunService runService;
    private final ConsoleReporter reporter;

    public PrepareRemediationBranchesCommand(
            RemediationBranchPreparationService branchService,
            Supplier<GitWorktreeConfig> configSource,
            RemediationRunService runService,
            ConsoleReporter reporter) {
        this.branchService = Objects.requireNonNull(branchService, "branchService");
        this.configSource = Objects.requireNonNull(configSource, "configSource");
        this.runService = Objects.requireNonNull(runService, "runService");
        this.reporter = Objects.requireNonNull(reporter, "reporter");
    }

    public ExitCode run() {
        return runAndReport(null).exitCode();
    }

    /**
     * @param pilotFilter when non-null, narrows the plan to exactly this one library (in its real
     *                    severity bucket) before any branch is created -- a
     *                    {@code remediate --dependency} pilot run. {@code null} means the whole plan,
     *                    the original unfiltered behaviour.
     */
    public BranchPreparationStageResult runAndReport(DependencyCoordinates pilotFilter) {
        RemediationBranchOutcome outcome;
        try {
            outcome = pilotFilter == null
                    ? branchService.prepareBranches()
                    : branchService.prepareBranches(pilotFilter.groupId(), pilotFilter.artifactId());
        } catch (DependencyNotFoundException e) {
            reporter.printDependencyNotFoundError(e.getMessage());
            return new BranchPreparationStageResult(ExitCode.REMEDIATION_SOURCE_ERROR, null);
        } catch (RemediationSourceException e) {
            reporter.printRemediationSourceError(e.getMessage());
            return new BranchPreparationStageResult(ExitCode.REMEDIATION_SOURCE_ERROR, null);
        } catch (ConfigurationException e) {
            reporter.printConfigError(e.getMessage());
            return new BranchPreparationStageResult(ExitCode.CONFIG_ERROR, null);
        } catch (GitCommandException e) {
            reporter.printGitOperationError(e.getMessage());
            return new BranchPreparationStageResult(ExitCode.GIT_OPERATION_ERROR, null);
        } catch (RuntimeException e) {
            reporter.printUnexpectedError();
            return new BranchPreparationStageResult(ExitCode.UNEXPECTED_ERROR, null);
        }

        reporter.printRunId(outcome.runId());
        for (String group : outcome.emptyGroups()) {
            reporter.printSeverityGroupEmpty(group);
        }
        if (outcome.baseCommitSha() != null) {
            reporter.printBaseCommit(outcome.baseCommitSha());
        }
        for (CreatedBranch branch : outcome.created()) {
            reporter.printBranchCreated(branch.severity(), branch.branchName());
        }
        for (GroupFailure failure : outcome.failures()) {
            reporter.printSeverityGroupFailed(failure.group(), failure.message());
        }

        if (outcome.created().isEmpty() && !outcome.failures().isEmpty()) {
            return new BranchPreparationStageResult(ExitCode.GIT_OPERATION_ERROR, null);
        }

        String workspacePath = outcome.created().isEmpty() ? "" : configSource.get().repoPath().toString();

        RunManifest manifest;
        try {
            manifest = runService.recordRun(outcome, workspacePath);
        } catch (RunManifestWriteException e) {
            reporter.printRunManifestWriteError(e.getMessage());
            return new BranchPreparationStageResult(ExitCode.REPORT_WRITE_ERROR, null);
        }

        reporter.printRunManifestSummary(manifest.units().size(), manifest.manualAnalysisRequired().size());
        reporter.printRunManifestLocation(runService.manifestPathFor(manifest.runId()));

        if (pilotFilter != null && !manifest.units().isEmpty()) {
            reporter.printPilotSelection(manifest.units().get(0).severity(), manifest.units().size());
        }

        ExitCode exitCode = outcome.failures().isEmpty() ? ExitCode.SUCCESS : ExitCode.GIT_OPERATION_ERROR;
        return new BranchPreparationStageResult(exitCode, manifest);
    }
}
