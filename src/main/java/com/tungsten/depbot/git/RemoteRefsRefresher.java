package com.tungsten.depbot.git;

import java.nio.file.Path;
import java.util.Objects;

/**
 * Brings every remote branch and tag up to date, once, before an assessment runs.
 *
 * <p><strong>This is the orchestrator's step and nobody else's.</strong> Neither Claude phase is
 * permitted to fetch -- see {@code ClaudeToolPolicy.FORBIDDEN_GIT_PUBLISHING}. If an agent could refresh refs
 * mid-analysis, the evidence it reports and the commit the orchestrator later resolves for the ref it
 * chose could come from two different states of the remote, and nothing downstream would be able to
 * tell.
 *
 * <p>A fetch failure is reported, not thrown. Being unable to reach the remote is an ordinary
 * condition -- no network, no VPN, a proxy in the way -- and it does not make the repository
 * unusable: the refs already present are still real refs, and the assessment is told plainly that
 * they may be out of date so it can weigh its conclusions accordingly. Aborting instead would mean a
 * transient network problem stopped every library in the run, while proceeding silently would mean an
 * assessment reasoning from a stale view of the remote and never knowing it.
 */
public final class RemoteRefsRefresher {

    public static final String DEFAULT_REMOTE = "origin";

    private final GitCommandRunner git;

    public RemoteRefsRefresher(GitCommandRunner git) {
        this.git = Objects.requireNonNull(git, "git");
    }

    public RefsRefreshOutcome refresh(Path repoPath) {
        return refresh(repoPath, DEFAULT_REMOTE);
    }

    public RefsRefreshOutcome refresh(Path repoPath, String remote) {
        Objects.requireNonNull(repoPath, "repoPath");
        Objects.requireNonNull(remote, "remote");
        try {
            git.fetchBranchesAndTags(repoPath, remote);
            return RefsRefreshOutcome.refreshed(remote);
        } catch (GitCommandException e) {
            return RefsRefreshOutcome.failed(
                    "Could not refresh refs from " + remote + ", so the refs already present may be out "
                            + "of date: " + e.getMessage());
        }
    }
}
