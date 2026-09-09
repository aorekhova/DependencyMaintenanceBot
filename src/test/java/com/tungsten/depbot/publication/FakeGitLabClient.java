package com.tungsten.depbot.publication;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * An in-memory stand-in for the real GitLab API, so tests exercise {@link GitLabPublicationService}'s
 * own idempotency and orchestration logic without ever reaching a network. Never used by production
 * code -- test-support only.
 */
public final class FakeGitLabClient implements GitLabClient {

    private final List<FakeMergeRequest> mergeRequests = new ArrayList<>();
    private final Map<String, List<String>> commitComments = new LinkedHashMap<>();
    private final List<FakeIssue> issues = new ArrayList<>();
    private int nextMergeRequestIid = 1;
    private int nextIssueIid = 1;
    private int callCount = 0;
    private int callNumberToFail = -1;
    private RuntimeException failureException;
    private ProjectMetadata project = new ProjectMetadata("123", "group/webapp", "https://gitlab.example.invalid/group/webapp");

    /**
     * The {@code callNumber}-th call this fake receives, counting every {@code GitLabClient} method
     * together starting at 1, throws {@code exception} instead of acting -- and every call before it
     * succeeds normally. Lets a test simulate a failure landing at one exact point in a real publish
     * sequence (e.g. "the Merge Request was created, then the network failed posting the first report")
     * rather than only ever failing the very next call made.
     */
    public void failOnCallNumber(int callNumber, RuntimeException exception) {
        this.callNumberToFail = callNumber;
        this.failureException = exception;
    }

    private void maybeFail() {
        callCount++;
        if (callCount == callNumberToFail) {
            callNumberToFail = -1;
            throw failureException;
        }
    }

    /** Configures the project metadata {@link #fetchProject()} returns -- defaults to a plausible project. */
    public void setProject(ProjectMetadata project) {
        this.project = project;
    }

    @Override
    public ProjectMetadata fetchProject() {
        maybeFail();
        return project;
    }

    /**
     * Pre-seeds a Merge Request in the given state, as if a human had already acted on a previous run's
     * publication -- never how production code creates one (see {@link #createMergeRequest}).
     */
    public int seedMergeRequest(String sourceBranch, String targetBranch, MergeRequestState state) {
        FakeMergeRequest mergeRequest =
                new FakeMergeRequest(nextMergeRequestIid++, sourceBranch, targetBranch, "seeded");
        mergeRequest.state = state;
        mergeRequests.add(mergeRequest);
        return mergeRequest.iid;
    }

    /** Pre-seeds a second Merge Request with the same source branch, to test the fail-closed duplicate path. */
    public void seedDuplicateMergeRequest(String sourceBranch, String targetBranch) {
        seedMergeRequest(sourceBranch, targetBranch, MergeRequestState.OPEN);
    }

    /** Pre-seeds an Issue in the given state, whose description already contains {@code marker}. */
    public int seedIssue(String marker, IssueState state) {
        FakeIssue issue = new FakeIssue(nextIssueIid++, "seeded", marker + "\n\nseeded issue");
        issue.state = state;
        issues.add(issue);
        return issue.iid;
    }

    @Override
    public Optional<MergeRequestRef> findMergeRequestBySourceBranch(String sourceBranch) {
        maybeFail();
        List<FakeMergeRequest> matches = mergeRequests.stream()
                .filter(mr -> mr.sourceBranch.equals(sourceBranch))
                .toList();
        if (matches.isEmpty()) {
            return Optional.empty();
        }
        if (matches.size() > 1) {
            throw new GitLabPublicationException("Found " + matches.size()
                    + " merge requests with source branch \"" + sourceBranch
                    + "\" -- refusing to guess which one is authoritative.");
        }
        FakeMergeRequest mr = matches.get(0);
        return Optional.of(new MergeRequestRef(mr.iid, mr.webUrl(), mr.state));
    }

    @Override
    public MergeRequestRef createMergeRequest(
            String sourceBranch, String targetBranch, String title, String description) {
        maybeFail();
        FakeMergeRequest mergeRequest = new FakeMergeRequest(nextMergeRequestIid++, sourceBranch, targetBranch, title);
        mergeRequest.description = description;
        mergeRequests.add(mergeRequest);
        return new MergeRequestRef(mergeRequest.iid, mergeRequest.webUrl(), mergeRequest.state);
    }

    @Override
    public void updateMergeRequestDescription(int mergeRequestIid, String description) {
        maybeFail();
        for (FakeMergeRequest mergeRequest : mergeRequests) {
            if (mergeRequest.iid == mergeRequestIid) {
                mergeRequest.description = description;
                return;
            }
        }
        throw new GitLabPublicationException("No such merge request: " + mergeRequestIid);
    }

    @Override
    public boolean commitCommentContains(String commitSha, String marker) {
        maybeFail();
        return commitComments.getOrDefault(commitSha, List.of()).stream().anyMatch(body -> body.contains(marker));
    }

    @Override
    public void postCommitComment(String commitSha, String body) {
        maybeFail();
        commitComments.computeIfAbsent(commitSha, sha -> new ArrayList<>()).add(body);
    }

    @Override
    public Optional<IssueRef> findIssueContaining(String marker) {
        maybeFail();
        List<FakeIssue> matches = issues.stream()
                .filter(issue -> issue.description.contains(marker))
                .toList();
        if (matches.isEmpty()) {
            return Optional.empty();
        }
        if (matches.size() > 1) {
            throw new GitLabPublicationException("Found " + matches.size()
                    + " issues matching marker \"" + marker + "\" -- refusing to guess which one is authoritative.");
        }
        FakeIssue issue = matches.get(0);
        return Optional.of(new IssueRef(issue.iid, issue.webUrl(), issue.state));
    }

    @Override
    public IssueRef createIssue(String title, String description) {
        maybeFail();
        FakeIssue issue = new FakeIssue(nextIssueIid++, title, description);
        issues.add(issue);
        return new IssueRef(issue.iid, issue.webUrl(), issue.state);
    }

    // ---- test inspection ---------------------------------------------------------------------------

    /** Every {@link GitLabClient} method call this fake has received, regardless of which one. */
    public int callCount() {
        return callCount;
    }

    public int mergeRequestCount() {
        return mergeRequests.size();
    }

    public int issueCount() {
        return issues.size();
    }

    public String mergeRequestTargetBranch(int iid) {
        return mergeRequestByIid(iid).targetBranch;
    }

    public String mergeRequestTitle(int iid) {
        return mergeRequestByIid(iid).title;
    }

    public String mergeRequestDescription(int iid) {
        return mergeRequestByIid(iid).description;
    }

    public MergeRequestState mergeRequestState(int iid) {
        return mergeRequestByIid(iid).state;
    }

    public List<String> commitComments(String commitSha) {
        return List.copyOf(commitComments.getOrDefault(commitSha, List.of()));
    }

    public String issueTitle(int iid) {
        return issueByIid(iid).title;
    }

    public String issueDescription(int iid) {
        return issueByIid(iid).description;
    }

    private FakeMergeRequest mergeRequestByIid(int iid) {
        return mergeRequests.stream().filter(mr -> mr.iid == iid).findFirst()
                .orElseThrow(() -> new AssertionError("no fake merge request with iid " + iid));
    }

    private FakeIssue issueByIid(int iid) {
        return issues.stream().filter(issue -> issue.iid == iid).findFirst()
                .orElseThrow(() -> new AssertionError("no fake issue with iid " + iid));
    }

    private static final class FakeMergeRequest {
        private final int iid;
        private final String sourceBranch;
        private final String targetBranch;
        private final String title;
        private String description;
        private MergeRequestState state = MergeRequestState.OPEN;

        private FakeMergeRequest(int iid, String sourceBranch, String targetBranch, String title) {
            this.iid = iid;
            this.sourceBranch = sourceBranch;
            this.targetBranch = targetBranch;
            this.title = title;
        }

        private String webUrl() {
            return "https://gitlab.example.invalid/webapp/-/merge_requests/" + iid;
        }
    }

    private static final class FakeIssue {
        private final int iid;
        private final String title;
        private final String description;
        private IssueState state = IssueState.OPEN;

        private FakeIssue(int iid, String title, String description) {
            this.iid = iid;
            this.title = title;
            this.description = description;
        }

        private String webUrl() {
            return "https://gitlab.example.invalid/webapp/-/issues/" + iid;
        }
    }
}
