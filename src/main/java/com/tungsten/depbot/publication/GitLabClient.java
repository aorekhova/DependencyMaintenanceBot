package com.tungsten.depbot.publication;

import java.util.Optional;

/**
 * The narrow slice of the GitLab API this application ever calls -- Merge Requests, commit comments and
 * Issues, and only the lookups needed to make every one of those idempotent on a retried run. Nothing
 * here ever merges, closes or reopens a Merge Request or Issue; there is deliberately no method that
 * could.
 *
 * <p>Every "publish" method is meant to be called only after its matching "find" method (or an
 * equivalent existence check) has already come back empty -- {@link GitLabPublicationService} owns that
 * sequencing. A real implementation ({@code GitLabApiClient}) talks to the actual GitLab REST API; tests
 * use an in-memory fake that never touches the network.
 *
 * <p>Both find methods search <strong>every</strong> state (open, closed, and -- for a Merge Request --
 * merged too), never only {@code state=opened}: a retry must discover an already-closed or already-merged
 * object exactly as reliably as an open one, so it is never mistaken for "nothing exists yet" and
 * duplicated. If more than one distinct object matches the same stable-identity marker, the
 * implementation throws {@link GitLabPublicationException} rather than silently picking one -- an
 * ambiguous identity is never guessed at.
 */
public interface GitLabClient {

    /**
     * Read-only project metadata GitLab itself reports for the configured project -- used only by
     * {@link RemoteIdentityVerifier}, before any mutating call, to confirm the git remote this checkout
     * pushes to and the GitLab project this client mutates are genuinely the same project.
     */
    ProjectMetadata fetchProject();

    /**
     * The Merge Request whose source branch is exactly {@code sourceBranch}, in any state, if one already
     * exists.
     *
     * @throws GitLabPublicationException if more than one distinct Merge Request matches
     */
    Optional<MergeRequestRef> findMergeRequestBySourceBranch(String sourceBranch);

    /** Opens a new Merge Request. Never merges it -- that is a human's decision, always. */
    MergeRequestRef createMergeRequest(String sourceBranch, String targetBranch, String title, String description);

    /** Overwrites a Merge Request's description -- always safe to repeat, never creates anything new. */
    void updateMergeRequestDescription(int mergeRequestIid, String description);

    /**
     * Whether a comment containing {@code marker} already exists on this commit -- the idempotency check
     * a retried publish makes before {@link #postCommitComment} to avoid posting the same report twice.
     */
    boolean commitCommentContains(String commitSha, String marker);

    /** Posts a comment on the given commit -- how a per-commit {@code RemediationReport} reaches GitLab. */
    void postCommitComment(String commitSha, String body);

    /**
     * The Issue whose description contains {@code marker}, in any state, if one already exists -- the
     * idempotency check a retried publish makes before {@link #createIssue}.
     *
     * @throws GitLabPublicationException if more than one distinct Issue matches
     */
    Optional<IssueRef> findIssueContaining(String marker);

    /** Opens a new Issue -- how a Human Review Report for a group with no commit reaches GitLab. */
    IssueRef createIssue(String title, String description);
}
