package com.tungsten.depbot.publication;

import java.util.Objects;

/**
 * A GitLab Merge Request identified well enough to be found again on a later, retried run.
 *
 * <p>{@code state} is the real, discovered GitLab state -- {@code OPEN} for a freshly created one, or
 * whatever {@link GitLabClient#findMergeRequestBySourceBranch} discovered for an existing one. {@code
 * GitLabPublicationService} reads it to decide whether to proceed, verify, or stop -- see
 * {@link MergeRequestState}'s own javadoc: this application never sets it to anything but {@code OPEN}
 * by its own action.
 */
public record MergeRequestRef(int iid, String webUrl, MergeRequestState state) {

    public MergeRequestRef {
        Objects.requireNonNull(webUrl, "webUrl");
        Objects.requireNonNull(state, "state");
    }
}
