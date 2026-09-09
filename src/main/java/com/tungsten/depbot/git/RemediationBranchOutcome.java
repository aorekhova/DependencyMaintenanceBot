package com.tungsten.depbot.git;

import com.tungsten.depbot.remediation.RemediationPlan;

import java.util.List;

/**
 * The result of preparing branches for one run: no checkout is ever touched here, so unlike the
 * old worktree-based outcome there is no path on disk to report -- only branch names.
 *
 * <p>{@code runId} is always present, even when every severity group was empty. {@code
 * baseCommitSha} is {@code null} only in that empty case, since git was never queried.
 */
public record RemediationBranchOutcome(
        RemediationPlan plan,
        String runId,
        String baseCommitSha,
        List<CreatedBranch> created,
        List<String> emptyGroups,
        List<GroupFailure> failures) {

    public RemediationBranchOutcome {
        created = created == null ? List.of() : List.copyOf(created);
        emptyGroups = emptyGroups == null ? List.of() : List.copyOf(emptyGroups);
        failures = failures == null ? List.of() : List.copyOf(failures);
    }
}
