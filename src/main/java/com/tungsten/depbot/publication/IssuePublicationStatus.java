package com.tungsten.depbot.publication;

/**
 * What a Human Review group's GitLab Issue publication has become. Simpler than {@code
 * RemediationCohort.PublicationStatus} -- a Human Review group never has a branch, a push or a Merge
 * Request, only the one Issue, found or created.
 */
public enum IssuePublicationStatus {
    /** A Human Review Report exists locally; its Issue has not been published yet. */
    READY_TO_PUBLISH,
    /** The Issue exists in GitLab (found already open, or newly created). */
    PUBLISHED,
    /**
     * An Issue with this group's stable identity already exists and is CLOSED. The bot never reopens it
     * automatically -- distinct from {@link #PUBLISHED} (would wrongly imply it is open and actionable)
     * and {@link #PUBLICATION_FAILED} (nothing failed; the Issue's content already matches, only its
     * closed state needs a human decision).
     */
    ISSUE_CLOSED,
    /** Publication for this group's Issue did not complete. The local Human Review Report is untouched. */
    PUBLICATION_FAILED
}
