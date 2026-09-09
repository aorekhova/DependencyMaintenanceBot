package com.tungsten.depbot.publication;

/**
 * A Merge Request's real state in GitLab, as discovered by a stable-identity lookup -- never something
 * this application produces by mutating a Merge Request's state itself (it never closes or merges one).
 */
public enum MergeRequestState {
    OPEN,
    CLOSED,
    MERGED
}
