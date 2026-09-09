package com.tungsten.depbot.publication;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.humanreview.HumanReviewReport;
import com.tungsten.depbot.humanreview.HumanReviewService;
import com.tungsten.depbot.remediation.CohortIntegrationFailureOutcome;
import com.tungsten.depbot.remediation.CohortsIndex;
import com.tungsten.depbot.remediation.RejectedGroupOutcome;
import com.tungsten.depbot.remediation.RemediationCohort;
import com.tungsten.depbot.remediation.RemediationReport;
import com.tungsten.depbot.remediation.RemediationSummary;
import com.tungsten.depbot.remediation.RemediationSummaryEntry;
import com.tungsten.depbot.run.RemediationRunService;
import com.tungsten.depbot.validation.ValidationStatus;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The publication layer, entirely new and entirely separate from the remediation/grouping/Human Review
 * core flow it sits on top of: verifies the git remote is genuinely the configured GitLab project, pushes
 * each eligible cohort's already-committed shared branch, opens or reuses one Merge Request per cohort
 * targeting its verified source ref, publishes every successful commit's own {@link RemediationReport}
 * against that commit's SHA, opens or reuses one GitLab Issue per Human Review group, and keeps every
 * Merge Request's description in sync with a whole-run summary. Claude is never involved in any of this
 * -- every fact published here already exists in an artifact Claude (or the bot's own validation/build
 * gates) produced earlier; this class only pushes, calls the GitLab API, and renders already-final
 * documents as Markdown.
 *
 * <p><strong>Never trusts {@code cohorts.json} blindly.</strong> {@link PublicationEligibility}
 * re-derives, from each commit's own {@link RemediationReport}, that dependency validation, the full
 * local build, isolated Jenkins and final integration Jenkins all genuinely succeeded before a single
 * mutating call is made; {@link CohortRepositoryPreflight} independently confirms the local branch on
 * disk still matches the exact commit sequence {@code cohorts.json} recorded. Both run fresh on every
 * {@code publish}/{@code preview} call -- publication can be a separate, later step reading files a
 * {@code remediate} run wrote earlier.
 *
 * <p><strong>Discovers before it ever mutates a Merge Request's branch.</strong> Before touching a
 * cohort, {@link #planCohort} looks up any existing Merge Request for its branch by stable identity
 * (source branch name) in <em>every</em> state. An {@code OPEN} one is never pushed to again (a second
 * push would change the diff a human may already be reviewing) -- only its remote branch is confirmed,
 * read-only, to still match the expected tip; a mismatch fails closed rather than force-pushing. A
 * {@code CLOSED} or {@code MERGED} one is never pushed to, never recreated, and never reopened -- the
 * cohort is reported {@link RemediationCohort.PublicationStatus#MERGE_REQUEST_CLOSED} or {@link
 * RemediationCohort.PublicationStatus#MERGED} and nothing further happens for it. Only when no Merge
 * Request exists at all does this class push and create one. This is what makes a retry unable to ever
 * undo a human's decision to close or merge a Merge Request.
 *
 * <p><strong>Idempotent by construction, not by any extra bookkeeping.</strong> Every GitLab-mutating
 * call is preceded by a "does this already exist" check keyed on something stable across retries -- the
 * branch name for the Merge Request, a marker embedded in the comment body for a commit's report, a
 * marker embedded in the issue description for a Human Review group -- so re-running {@link
 * #publish(String, CohortsIndex, RemediationSummary)} after a partial failure resumes exactly where it
 * left off. A cohort or group whose publication fails is recorded as {@link
 * RemediationCohort.PublicationStatus#PUBLICATION_FAILED} / {@link IssuePublicationStatus#PUBLICATION_FAILED}
 * and nothing about its already-validated local commits is ever touched, reset or discarded because of it.
 */
public final class GitLabPublicationService {

    /** The run-wide GitLab publication record -- a supplement to {@code cohorts.json}, never a replacement. */
    public static final String PUBLICATION_FILE = "publication.json";

    /**
     * Every remediation branch this application ever pushes starts with this prefix (see {@code
     * RemediationBranchName.PREFIX}, duplicated here as a literal rather than imported so this class
     * never depends on -- and can never be tempted to call -- the naming algorithm itself; publication
     * only ever reads a branch name that already exists in {@code cohorts.json}, never computes one.
     */
    private static final String REMEDIATION_BRANCH_NAMESPACE = "remediation/";

    /**
     * Literal filenames duplicated here (never imported from {@code remediation}, matching
     * {@link #REMEDIATION_BRANCH_NAMESPACE}'s own precedent) -- both are written by
     * {@code VulnerabilityRemediationService} as siblings of a Human Review group's own
     * {@code human-review-report.json}; at most one of the two ever exists for a given group.
     */
    private static final String REJECTED_GROUP_OUTCOME_FILE = "rejected-group-outcome.json";
    private static final String COHORT_INTEGRATION_FAILURE_FILE = "cohort-integration-failure.json";

    private final Path repoPath;
    private final GitCommandRunner git;
    private final GitLabConfig config;
    private final GitLabClient gitLabClient;
    private final RemediationRunService runService;
    private final RemediationReportMarkdownRenderer remediationReportRenderer;
    private final HumanReviewReportMarkdownRenderer humanReviewReportRenderer;
    private final PublicationSummaryMarkdownRenderer summaryRenderer;
    private final PublicationIndexJsonRenderer publicationIndexJsonRenderer;
    private final RemoteIdentityVerifier remoteIdentityVerifier;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public GitLabPublicationService(
            Path repoPath,
            GitCommandRunner git,
            GitLabConfig config,
            GitLabClient gitLabClient,
            RemediationRunService runService) {
        this(repoPath, git, config, gitLabClient, runService, new RemoteIdentityVerifier());
    }

    /**
     * As the five-argument constructor, but with an explicit {@link RemoteIdentityVerifier} -- the one
     * piece worth injecting from outside this package even in production-shaped code, since a test that
     * exercises real git push mechanics against a local fixture repository cannot also satisfy a real
     * identity check against a real GitLab host (see {@code PublishCommandTest}, which needs exactly
     * this).
     */
    public GitLabPublicationService(
            Path repoPath,
            GitCommandRunner git,
            GitLabConfig config,
            GitLabClient gitLabClient,
            RemediationRunService runService,
            RemoteIdentityVerifier remoteIdentityVerifier) {
        this(repoPath, git, config, gitLabClient, runService,
                new RemediationReportMarkdownRenderer(), new HumanReviewReportMarkdownRenderer(),
                new PublicationSummaryMarkdownRenderer(), new PublicationIndexJsonRenderer(),
                remoteIdentityVerifier);
    }

    GitLabPublicationService(
            Path repoPath,
            GitCommandRunner git,
            GitLabConfig config,
            GitLabClient gitLabClient,
            RemediationRunService runService,
            RemediationReportMarkdownRenderer remediationReportRenderer,
            HumanReviewReportMarkdownRenderer humanReviewReportRenderer,
            PublicationSummaryMarkdownRenderer summaryRenderer,
            PublicationIndexJsonRenderer publicationIndexJsonRenderer,
            RemoteIdentityVerifier remoteIdentityVerifier) {
        this.repoPath = Objects.requireNonNull(repoPath, "repoPath");
        this.git = Objects.requireNonNull(git, "git");
        this.config = Objects.requireNonNull(config, "config");
        this.gitLabClient = Objects.requireNonNull(gitLabClient, "gitLabClient");
        this.runService = Objects.requireNonNull(runService, "runService");
        this.remediationReportRenderer =
                Objects.requireNonNull(remediationReportRenderer, "remediationReportRenderer");
        this.humanReviewReportRenderer =
                Objects.requireNonNull(humanReviewReportRenderer, "humanReviewReportRenderer");
        this.summaryRenderer = Objects.requireNonNull(summaryRenderer, "summaryRenderer");
        this.publicationIndexJsonRenderer =
                Objects.requireNonNull(publicationIndexJsonRenderer, "publicationIndexJsonRenderer");
        this.remoteIdentityVerifier = Objects.requireNonNull(remoteIdentityVerifier, "remoteIdentityVerifier");
    }

    /**
     * Every read-only check {@link #publish} would perform -- remote identity, eligibility, repository
     * preflight, and discovering any already-existing Merge Request/Issue -- rendered as a preview,
     * without a single mutating call. Multi-cohort: one run can contain several cohorts (different
     * verified source refs/SHAs), and each gets its own, separately reported {@link
     * PublicationPreview.CohortPreview}.
     */
    public PublicationPreview preview(String runId, CohortsIndex cohortsIndex, RemediationSummary summary) {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(cohortsIndex, "cohortsIndex");
        Objects.requireNonNull(summary, "summary");

        VerificationResult identity = verifyRemoteIdentity();
        List<PublicationPreview.CohortPreview> cohortPreviews = new ArrayList<>();
        for (CohortsIndex.Entry cohort : cohortsIndex.cohorts()) {
            if (!identity.verified()) {
                cohortPreviews.add(ineligibleCohortPreview(cohort, identity.reason()));
                continue;
            }
            cohortPreviews.add(toCohortPreview(planCohort(cohort)));
        }

        List<PublicationPreview.HumanReviewGroupPreview> humanReviewPreviews = new ArrayList<>();
        for (HumanReviewGroup group : distinctHumanReviewGroups(summary)) {
            humanReviewPreviews.add(toHumanReviewGroupPreview(runId, group, identity));
        }

        return new PublicationPreview(runId, cohortPreviews, humanReviewPreviews);
    }

    /**
     * Publishes every eligible cohort in {@code cohortsIndex} and every distinct Human Review group in
     * {@code summary}, then writes {@value #PUBLICATION_FILE}. Safe to call again for the same run:
     * nothing already published is republished or duplicated, and nothing already closed or merged by a
     * human is ever reopened, recreated, or pushed to again.
     */
    public PublicationIndex publish(String runId, CohortsIndex cohortsIndex, RemediationSummary summary) {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(cohortsIndex, "cohortsIndex");
        Objects.requireNonNull(summary, "summary");

        VerificationResult identity = verifyRemoteIdentity();
        if (!identity.verified()) {
            return writeAndReturn(runId, identityFailureIndex(runId, cohortsIndex, summary, identity.reason()));
        }

        List<PublicationIndex.CohortPublication> cohortPublications = new ArrayList<>();
        List<RunPublicationSummary.CommitSummary> publishedCommitSummaries = new ArrayList<>();
        for (CohortsIndex.Entry cohort : cohortsIndex.cohorts()) {
            CohortResult result = executeCohortPlan(planCohort(cohort));
            cohortPublications.add(result.publication());
            publishedCommitSummaries.addAll(result.commitSummaries());
        }

        List<HumanReviewGroup> humanReviewGroups = distinctHumanReviewGroups(summary);
        List<PublicationIndex.HumanReviewPublication> humanReviewPublications = new ArrayList<>();
        List<RunPublicationSummary.HumanReviewSummary> humanReviewSummaries = new ArrayList<>();
        for (HumanReviewGroup group : humanReviewGroups) {
            PublicationIndex.HumanReviewPublication publication = publishHumanReviewGroup(runId, group);
            humanReviewPublications.add(publication);
            humanReviewSummaries.add(new RunPublicationSummary.HumanReviewSummary(
                    group.memberCoordinates(), publication.issueUrl()));
        }

        String runSummaryMarkdown = summaryRenderer.render(
                new RunPublicationSummary(runId, publishedCommitSummaries, humanReviewSummaries));
        for (PublicationIndex.CohortPublication cohort : cohortPublications) {
            if (cohort.status() == RemediationCohort.PublicationStatus.MERGE_REQUEST_OPENED
                    && cohort.mergeRequestIid() != null) {
                gitLabClient.updateMergeRequestDescription(cohort.mergeRequestIid(), runSummaryMarkdown);
            }
        }

        return writeAndReturn(runId, new PublicationIndex(runId, cohortPublications, humanReviewPublications));
    }

    private VerificationResult verifyRemoteIdentity() {
        return remoteIdentityVerifier.verify(git, repoPath, config.remoteName(), gitLabClient, config);
    }

    private PublicationIndex identityFailureIndex(
            String runId, CohortsIndex cohortsIndex, RemediationSummary summary, String reason) {
        List<PublicationIndex.CohortPublication> cohorts = cohortsIndex.cohorts().stream()
                .map(cohort -> failedCohortResult(cohort, reason).publication())
                .toList();
        List<PublicationIndex.HumanReviewPublication> humanReviewGroups = distinctHumanReviewGroups(summary).stream()
                .map(group -> new PublicationIndex.HumanReviewPublication(group.groupKey(),
                        group.memberCoordinates(), IssuePublicationStatus.PUBLICATION_FAILED, null, null, reason))
                .toList();
        return new PublicationIndex(runId, cohorts, humanReviewGroups);
    }

    private PublicationIndex writeAndReturn(String runId, PublicationIndex index) {
        runService.writeRunArtifact(
                runService.runDirectoryFor(runId).resolve(PUBLICATION_FILE),
                publicationIndexJsonRenderer.render(index));
        return index;
    }

    // ---- planning: every read-only step, shared between preview() and publish() ---------------------

    /**
     * Everything read-only that must happen before a cohort can be mutated: load every commit's own
     * report, evaluate {@link PublicationEligibility}, run {@link CohortRepositoryPreflight}, and
     * discover any already-existing Merge Request for the cohort's branch, in any state. Never mutates
     * anything -- {@link #preview} renders this directly; {@link #publish} additionally executes it via
     * {@link #executeCohortPlan}.
     */
    private CohortPlan planCohort(CohortsIndex.Entry cohort) {
        Map<String, RemediationReport> reportsByCommitSha = new LinkedHashMap<>();
        for (CohortsIndex.Commit commit : cohort.commits()) {
            try {
                reportsByCommitSha.put(commit.commitSha(), readRemediationReport(commit.remediationReportPath()));
            } catch (RuntimeException e) {
                return CohortPlan.ineligible(cohort, "could not read the Remediation Report for commit "
                        + commit.commitSha() + " (group " + commit.groupId() + "): " + e.getMessage());
            }
        }

        EligibilityResult eligibility = PublicationEligibility.evaluate(cohort, reportsByCommitSha);
        if (!eligibility.eligible()) {
            return CohortPlan.ineligible(cohort, eligibility.reason());
        }

        PreflightResult preflight = CohortRepositoryPreflight.verify(git, repoPath, cohort);
        if (!preflight.ok()) {
            return CohortPlan.ineligible(cohort, preflight.reason());
        }

        Optional<MergeRequestRef> existing;
        try {
            existing = gitLabClient.findMergeRequestBySourceBranch(cohort.branchName());
        } catch (RuntimeException e) {
            return CohortPlan.ineligible(cohort, "could not look up an existing merge request: " + e.getMessage());
        }

        return CohortPlan.planned(cohort, reportsByCommitSha, preflight.expectedTip(), existing.orElse(null));
    }

    /**
     * Carries out exactly the policy required for each of a discovered Merge Request's possible states
     * (or its absence) -- see this class's own javadoc for the full rationale.
     */
    private CohortResult executeCohortPlan(CohortPlan plan) {
        CohortsIndex.Entry cohort = plan.cohort();
        if (!plan.eligible()) {
            return failedCohortResult(cohort, plan.ineligibleReason());
        }

        try {
            MergeRequestRef existing = plan.existingMergeRequest();
            if (existing == null) {
                pushAndVerify(cohort, plan.expectedTip());
                MergeRequestRef created = gitLabClient.createMergeRequest(
                        cohort.branchName(), targetBranchFor(cohort.verifiedSourceRef()),
                        mergeRequestTitle(cohort), "_(summary pending)_");
                return publishCommitsAndFinish(plan, created, RemediationCohort.PublicationStatus.MERGE_REQUEST_OPENED);
            }

            return switch (existing.state()) {
                case OPEN -> {
                    String remoteSha = git.lsRemoteSha(repoPath, config.remoteName(), cohort.branchName());
                    if (!plan.expectedTip().equals(remoteSha)) {
                        yield failedCohortResult(cohort, "remote branch " + cohort.branchName()
                                + " does not match the expected tip (expected " + plan.expectedTip()
                                + ", remote has " + remoteSha
                                + ") -- an open Merge Request already exists, so this is never force-pushed");
                    }
                    yield publishCommitsAndFinish(plan, existing, RemediationCohort.PublicationStatus.MERGE_REQUEST_OPENED);
                }
                case CLOSED -> terminalDiscoveredState(cohort, existing, RemediationCohort.PublicationStatus.MERGE_REQUEST_CLOSED);
                case MERGED -> terminalDiscoveredState(cohort, existing, RemediationCohort.PublicationStatus.MERGED);
            };
        } catch (RuntimeException e) {
            return failedCohortResult(cohort, e.getMessage());
        }
    }

    /**
     * A Merge Request was discovered CLOSED or MERGED: no push, no branch recreation, no reopening, no
     * new Merge Request, and -- deliberately -- no commit reports posted either, so a retry never looks
     * like fresh activity on an object a human has already closed or merged.
     */
    private CohortResult terminalDiscoveredState(
            CohortsIndex.Entry cohort, MergeRequestRef existing, RemediationCohort.PublicationStatus status) {
        return new CohortResult(new PublicationIndex.CohortPublication(
                cohort.branchName(), cohort.verifiedSourceRef(), cohort.verifiedSourceSha(), status,
                existing.webUrl(), existing.iid(), List.of(), null), List.of());
    }

    /**
     * Pushes the cohort's branch -- only ever reached when no Merge Request exists for it yet -- and
     * confirms, read-only, that the remote now genuinely carries the expected tip.
     */
    private void pushAndVerify(CohortsIndex.Entry cohort, String expectedTip) {
        if (!cohort.branchName().startsWith(REMEDIATION_BRANCH_NAMESPACE)) {
            throw new GitLabPublicationException(
                    "refusing to push a branch outside the " + REMEDIATION_BRANCH_NAMESPACE + " namespace: "
                            + cohort.branchName());
        }
        git.push(repoPath, config.remoteName(), cohort.branchName());
        String remoteSha = git.lsRemoteSha(repoPath, config.remoteName(), cohort.branchName());
        if (!expectedTip.equals(remoteSha)) {
            throw new GitLabPublicationException("push to " + cohort.branchName() + " completed, but the "
                    + "remote tip (" + remoteSha + ") does not match the expected tip (" + expectedTip + ")");
        }
    }

    private CohortResult publishCommitsAndFinish(
            CohortPlan plan, MergeRequestRef mergeRequest, RemediationCohort.PublicationStatus status) {
        CohortsIndex.Entry cohort = plan.cohort();
        List<PublicationIndex.PublishedCommit> publishedCommits = new ArrayList<>();
        List<RunPublicationSummary.CommitSummary> commitSummaries = new ArrayList<>();
        for (CohortsIndex.Commit commit : cohort.commits()) {
            RemediationReport report = plan.reportsByCommitSha().get(commit.commitSha());
            publishCommitReport(commit, report);
            publishedCommits.add(new PublicationIndex.PublishedCommit(commit.groupId(), commit.commitSha(), true));
            commitSummaries.add(new RunPublicationSummary.CommitSummary(
                    commit.groupId(), commit.commitSha(), report.memberCoordinates(),
                    report.dependencyValidationStatus() == ValidationStatus.PASSED, report.fullyBuildValidated()));
        }
        PublicationIndex.CohortPublication publication = new PublicationIndex.CohortPublication(
                cohort.branchName(), cohort.verifiedSourceRef(), cohort.verifiedSourceSha(), status,
                mergeRequest.webUrl(), mergeRequest.iid(), publishedCommits, null);
        return new CohortResult(publication, commitSummaries);
    }

    private CohortResult failedCohortResult(CohortsIndex.Entry cohort, String reason) {
        return new CohortResult(new PublicationIndex.CohortPublication(
                cohort.branchName(), cohort.verifiedSourceRef(), cohort.verifiedSourceSha(),
                RemediationCohort.PublicationStatus.PUBLICATION_FAILED, null, null, List.of(), reason), List.of());
    }

    private record CohortResult(
            PublicationIndex.CohortPublication publication,
            List<RunPublicationSummary.CommitSummary> commitSummaries) {
    }

    /**
     * What planning learned about one cohort, before anything is executed. {@code reportsByCommitSha} and
     * {@code expectedTip} are populated only when {@code eligible}; {@code existingMergeRequest} is
     * {@code null} both when ineligible and when genuinely no Merge Request exists yet -- callers tell
     * the two apart via {@code eligible}.
     */
    private record CohortPlan(
            CohortsIndex.Entry cohort,
            boolean eligible,
            String ineligibleReason,
            Map<String, RemediationReport> reportsByCommitSha,
            String expectedTip,
            MergeRequestRef existingMergeRequest) {

        static CohortPlan ineligible(CohortsIndex.Entry cohort, String reason) {
            return new CohortPlan(cohort, false, reason, Map.of(), null, null);
        }

        static CohortPlan planned(
                CohortsIndex.Entry cohort, Map<String, RemediationReport> reports, String expectedTip,
                MergeRequestRef existingMergeRequest) {
            return new CohortPlan(cohort, true, null, reports, expectedTip, existingMergeRequest);
        }
    }

    private PublicationPreview.CohortPreview toCohortPreview(CohortPlan plan) {
        CohortsIndex.Entry cohort = plan.cohort();
        MergeRequestRef existing = plan.existingMergeRequest();
        return new PublicationPreview.CohortPreview(
                cohort.verifiedSourceRef(), cohort.verifiedSourceSha(), cohort.branchName(), cohort.branchName(),
                plan.eligible() ? plan.expectedTip() : null, targetBranchFor(cohort.verifiedSourceRef()),
                cohort.commits().stream().map(CohortsIndex.Commit::groupId).toList(),
                cohort.commits().stream().map(CohortsIndex.Commit::commitSha).toList(),
                plan.eligible(), plan.ineligibleReason(),
                existing == null ? null : existing.state(), existing == null ? null : existing.webUrl());
    }

    private PublicationPreview.CohortPreview ineligibleCohortPreview(CohortsIndex.Entry cohort, String reason) {
        return new PublicationPreview.CohortPreview(
                cohort.verifiedSourceRef(), cohort.verifiedSourceSha(), cohort.branchName(), cohort.branchName(),
                null, targetBranchFor(cohort.verifiedSourceRef()),
                cohort.commits().stream().map(CohortsIndex.Commit::groupId).toList(),
                cohort.commits().stream().map(CohortsIndex.Commit::commitSha).toList(),
                false, reason, null, null);
    }

    private PublicationPreview.HumanReviewGroupPreview toHumanReviewGroupPreview(
            String runId, HumanReviewGroup group, VerificationResult identity) {
        if (!identity.verified()) {
            return new PublicationPreview.HumanReviewGroupPreview(
                    group.groupKey(), group.memberCoordinates(), null, null);
        }
        String marker = humanReviewIssueMarker(runId, group.groupKey());
        Optional<IssueRef> existing = gitLabClient.findIssueContaining(marker);
        return new PublicationPreview.HumanReviewGroupPreview(
                group.groupKey(), group.memberCoordinates(),
                existing.map(IssueRef::state).orElse(null), existing.map(IssueRef::webUrl).orElse(null));
    }

    /** Posts the commit's own report, unless a retry finds it was already posted. */
    private void publishCommitReport(CohortsIndex.Commit commit, RemediationReport report) {
        String marker = commitReportMarker(commit.commitSha());
        if (gitLabClient.commitCommentContains(commit.commitSha(), marker)) {
            return;
        }
        String body = marker + "\n\n" + remediationReportRenderer.render(report);
        gitLabClient.postCommitComment(commit.commitSha(), body);
    }

    private PublicationIndex.HumanReviewPublication publishHumanReviewGroup(String runId, HumanReviewGroup group) {
        try {
            HumanReviewReport report = readHumanReviewReport(group.reportPath());
            RejectedGroupOutcome rejectedGroupOutcome = readOptionalJson(
                    group.reportPath().resolveSibling(REJECTED_GROUP_OUTCOME_FILE), RejectedGroupOutcome.class);
            CohortIntegrationFailureOutcome cohortIntegrationFailure = readOptionalJson(
                    group.reportPath().resolveSibling(COHORT_INTEGRATION_FAILURE_FILE),
                    CohortIntegrationFailureOutcome.class);
            String marker = humanReviewIssueMarker(runId, group.groupKey());

            Optional<IssueRef> existing = gitLabClient.findIssueContaining(marker);
            IssueRef issue = existing.orElseGet(() -> gitLabClient.createIssue(issueTitle(report),
                    issueBody(marker, report, runId, group, rejectedGroupOutcome, cohortIntegrationFailure)));
            IssuePublicationStatus status = existing.isPresent() && existing.get().state() == IssueState.CLOSED
                    ? IssuePublicationStatus.ISSUE_CLOSED
                    : IssuePublicationStatus.PUBLISHED;

            return new PublicationIndex.HumanReviewPublication(
                    group.groupKey(), group.memberCoordinates(), status, issue.webUrl(), issue.iid(), null);
        } catch (RuntimeException e) {
            return new PublicationIndex.HumanReviewPublication(
                    group.groupKey(), group.memberCoordinates(), IssuePublicationStatus.PUBLICATION_FAILED,
                    null, null, e.getMessage());
        }
    }

    private String issueBody(String marker, HumanReviewReport report, String runId, HumanReviewGroup group,
            RejectedGroupOutcome rejectedGroupOutcome, CohortIntegrationFailureOutcome cohortIntegrationFailure) {
        StringBuilder body = new StringBuilder();
        body.append(marker).append("\n\n");
        body.append(humanReviewReportRenderer.render(report, rejectedGroupOutcome, cohortIntegrationFailure));
        body.append("\n\n---\n\n");
        body.append("**Run:** ").append(runId).append('\n');
        if (group.verifiedSourceRef() != null) {
            body.append("**Verified source ref:** ").append(group.verifiedSourceRef());
            if (group.verifiedSourceSha() != null) {
                body.append(" @ `").append(group.verifiedSourceSha()).append('`');
            }
            body.append('\n');
        }
        return body.toString();
    }

    private static String issueTitle(HumanReviewReport report) {
        return "[Dependency Security] Human review required -- " + report.coordinates();
    }

    private static String mergeRequestTitle(CohortsIndex.Entry cohort) {
        String riskyPrefix = cohort.effectiveKind() == RemediationCohort.CohortKind.RISKY_SINGLE_GROUP
                ? "[Risky] " : "";
        return riskyPrefix + "Dependency remediation: " + cohort.commits().size()
                + (cohort.commits().size() == 1 ? " group" : " groups") + " (" + cohort.branchName() + ")";
    }

    /**
     * GitLab's Merge Request API takes a plain branch name, never the {@code refs/remotes/<remote>/}
     * path {@code SourceRefVerifier} always resolves to -- stripped here, once, rather than asking every
     * caller to know this.
     */
    private String targetBranchFor(String verifiedSourceRef) {
        String prefix = "refs/remotes/" + config.remoteName() + "/";
        return verifiedSourceRef.startsWith(prefix)
                ? verifiedSourceRef.substring(prefix.length())
                : verifiedSourceRef;
    }

    /**
     * Every distinct Human Review group in the run -- deduplicated by {@code humanReviewDirectory}, since
     * every member of a multi-library group shares that exact directory (one shared Human Review Report),
     * and the whole point is one Issue per <em>group</em>, never one per library inside it. A group whose
     * Human Review call never produced a usable report at all is left out here -- there is no report to
     * publish, and inventing Issue content from nothing is not this class's job.
     */
    private List<HumanReviewGroup> distinctHumanReviewGroups(RemediationSummary summary) {
        Map<String, List<RemediationSummaryEntry>> entriesByDirectory = new LinkedHashMap<>();
        for (RemediationSummaryEntry entry : summary.libraries()) {
            if (entry.humanReviewDirectory() == null || !Boolean.TRUE.equals(entry.humanReviewReportProduced())) {
                continue;
            }
            entriesByDirectory.computeIfAbsent(entry.humanReviewDirectory(), key -> new ArrayList<>()).add(entry);
        }

        List<HumanReviewGroup> groups = new ArrayList<>();
        for (Map.Entry<String, List<RemediationSummaryEntry>> entry : entriesByDirectory.entrySet()) {
            Path directory = Path.of(entry.getKey());
            // .../units/<unitId>/human-review/attempt-1 -- the unitId two levels up is already the
            // group's own stable identity (RunPaths.groupUnitId for a multi-member group), shared by
            // every member routed to this same directory.
            String groupKey = directory.getParent().getParent().getFileName().toString();
            List<String> members = entry.getValue().stream().map(RemediationSummaryEntry::coordinates).toList();
            RemediationSummaryEntry first = entry.getValue().get(0);
            groups.add(new HumanReviewGroup(groupKey, directory.resolve(HumanReviewService.REPORT_FILE),
                    members, first.sourceRefResolved(), first.sourceCommitSha()));
        }
        return groups;
    }

    private record HumanReviewGroup(
            String groupKey, Path reportPath, List<String> memberCoordinates,
            String verifiedSourceRef, String verifiedSourceSha) {
    }

    private RemediationReport readRemediationReport(String path) {
        return readJson(path, RemediationReport.class);
    }

    private HumanReviewReport readHumanReviewReport(Path path) {
        return readJson(path.toString(), HumanReviewReport.class);
    }

    private <T> T readJson(String path, Class<T> type) {
        try {
            return mapper.readValue(Files.readString(Path.of(path), StandardCharsets.UTF_8), type);
        } catch (IOException e) {
            throw new GitLabPublicationException("Could not read " + path + ": " + e.getMessage(), e);
        }
    }

    /**
     * As {@link #readJson(String, Class)}, but {@code null} when the file simply does not exist -- at
     * most one of {@code rejected-group-outcome.json}/{@code cohort-integration-failure.json} is ever
     * present for a given Human Review group, and neither exists at all for a group that was never
     * attempted automatically in the first place.
     */
    private <T> T readOptionalJson(Path path, Class<T> type) {
        if (!Files.exists(path)) {
            return null;
        }
        try {
            return mapper.readValue(Files.readString(path, StandardCharsets.UTF_8), type);
        } catch (IOException e) {
            throw new GitLabPublicationException("Could not read " + path + ": " + e.getMessage(), e);
        }
    }

    private static String commitReportMarker(String commitSha) {
        return "<!-- depbot-remediation-report:" + commitSha + " -->";
    }

    private static String humanReviewIssueMarker(String runId, String groupKey) {
        return "<!-- depbot-human-review:" + runId + ":" + groupKey + " -->";
    }
}
