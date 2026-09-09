package com.tungsten.depbot.run;

import com.fasterxml.jackson.annotation.JsonAlias;

import java.util.List;

/**
 * One library from the remediation plan, scoped to a single run and ready to be worked on.
 *
 * <p>{@code branch} is the severity group's branch, not a per-library one: every unit in the same
 * severity group shares it, since one branch accumulates that whole severity's work. Multiple
 * units can therefore point at the same branch -- each one's task file is meant to be worked
 * through in turn, on that shared branch.
 *
 * <p>{@code workspacePath} is the single managed checkout every unit of every severity runs in --
 * the same value for every unit of a run, since there is only one checkout, not one per severity.
 * The field was named {@code worktreePath} before each severity got its own {@code git worktree};
 * {@link JsonAlias} keeps old manifests written under that name readable.
 *
 * <p>{@code unitId} is unique within a run and is what names this unit's directory under
 * {@code reports/runs/<runId>/units/}, so the on-disk layout can be matched back to the manifest
 * by eye.
 *
 * <p>{@code status} starts at {@link #PENDING_STATUS} with {@code attempts} at {@code 0}. It moves
 * to {@link #RUNNING_STATUS} before starting work and then to exactly one of
 * {@link #COMMITTED_PENDING_VALIDATION_STATUS} or {@link #ROLLED_BACK_STATUS}.
 * {@code COMMITTED_PENDING_VALIDATION} means Claude exited cleanly <em>and</em> its change passed
 * the diff-policy check, so the orchestrator committed it -- it does <em>not</em> mean the upgrade
 * is correct: nothing builds or tests the result yet, which is why the name says "pending
 * validation" rather than just "committed". {@code ROLLED_BACK} covers every other outcome (Claude
 * failed or timed out, or the diff-policy check rejected the change) -- the attempt's patch and
 * logs are preserved, but the working tree is returned to what it was before this unit ran.
 */
public record RemediationUnit(
        String runId,
        String unitId,
        String severity,
        String groupId,
        String artifactId,
        String currentVersion,
        String targetVersion,
        List<String> vulnerabilityIds,
        String branch,
        @JsonAlias("worktreePath") String workspacePath,
        String taskFile,
        String status,
        int attempts) {

    public static final String PENDING_STATUS = "PENDING";
    public static final String RUNNING_STATUS = "RUNNING";
    public static final String COMMITTED_PENDING_VALIDATION_STATUS = "COMMITTED_PENDING_VALIDATION";
    public static final String ROLLED_BACK_STATUS = "ROLLED_BACK";

    public RemediationUnit {
        vulnerabilityIds = vulnerabilityIds == null ? List.of() : List.copyOf(vulnerabilityIds);
    }

    public String coordinates() {
        return groupId + ":" + artifactId;
    }

    /** Returns a copy with a new status and attempt count. Never mutates this instance. */
    public RemediationUnit withProgress(String newStatus, int newAttempts) {
        return new RemediationUnit(runId, unitId, severity, groupId, artifactId, currentVersion,
                targetVersion, vulnerabilityIds, branch, workspacePath, taskFile, newStatus, newAttempts);
    }
}
