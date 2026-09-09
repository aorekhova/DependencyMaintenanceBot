package com.tungsten.depbot.git;

/**
 * Whether the managed checkout's current branch was brought to the verified tip of its own remote
 * counterpart before the Vulnerability Analysis Engineer ever saw it.
 *
 * <p>{@code sourceRef} is {@code null} only when the run started detached -- there is no branch to
 * refresh against, and this is treated as failure, not as "nothing to do."
 */
public record RepositoryRefreshOutcome(
        String sourceRef, String verifiedSourceSha, RepositoryRefreshStatus status, String message) {

    public static RepositoryRefreshOutcome refreshed(String sourceRef, String verifiedSourceSha) {
        return new RepositoryRefreshOutcome(sourceRef, verifiedSourceSha, RepositoryRefreshStatus.REFRESHED,
                "The checkout was reset to " + sourceRef + " at " + verifiedSourceSha + ".");
    }

    public static RepositoryRefreshOutcome failed(String sourceRef, String message) {
        return new RepositoryRefreshOutcome(sourceRef, null, RepositoryRefreshStatus.FAILED, message);
    }

    public boolean refreshed() {
        return status == RepositoryRefreshStatus.REFRESHED;
    }
}
