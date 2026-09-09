package com.tungsten.depbot.publication;

import java.util.Objects;

/**
 * A GitLab Issue identified well enough to be found again on a later, retried run.
 *
 * <p>{@code state} is the real, discovered GitLab state -- see {@link IssueState}'s own javadoc: this
 * application never closes an Issue itself, only ever discovers one already closed by a human.
 */
public record IssueRef(int iid, String webUrl, IssueState state) {

    public IssueRef {
        Objects.requireNonNull(webUrl, "webUrl");
        Objects.requireNonNull(state, "state");
    }
}
