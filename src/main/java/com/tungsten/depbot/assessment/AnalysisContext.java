package com.tungsten.depbot.assessment;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/**
 * Everything one whole-batch Vulnerability Analysis Engineer call needs: which run it belongs to, the
 * repository it runs in and the state that repository is in, and every Mend finding in the batch --
 * seen together, in one call, so grouping decisions can be made from the full picture rather than one
 * finding at a time.
 *
 * <p>{@code currentBranch} and {@code currentHeadSha} are stated as facts for the same reason they were
 * on the old per-finding {@code AssessmentContext}: so the analysis can be told plainly not to assume
 * they are relevant to any given finding.
 */
public record AnalysisContext(
        String runId,
        Path workspace,
        String currentBranch,
        String currentHeadSha,
        boolean remoteRefsRefreshed,
        List<VulnerabilityWorkItem> workItems) {

    public AnalysisContext {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(workspace, "workspace");
        Objects.requireNonNull(workItems, "workItems");
        if (workItems.isEmpty()) {
            throw new IllegalArgumentException("workItems must not be empty");
        }
        workItems = List.copyOf(workItems);
    }
}
