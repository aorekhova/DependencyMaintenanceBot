package com.tungsten.depbot.publication;

/**
 * An Issue's real state in GitLab, as discovered by a stable-identity lookup -- never something this
 * application produces by mutating an Issue's state itself (it never closes one).
 */
public enum IssueState {
    OPEN,
    CLOSED
}
