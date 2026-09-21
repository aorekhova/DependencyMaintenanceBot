package com.tungsten.depbot.publication;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.git.RemediationBranchName;
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
 * core flow it sits on top of: verifies the git remote is genuinely the configured GitLab project, then
 * publishes every remediation GROUP as its own, isolated external publication unit -- ONE REMEDIATION
 * GROUP = ONE EXTERNAL PUBLICATION UNIT, never combined with a sibling's, even when several groups shared
 * one cohort/branch during remediation itself. Claude is never involved in any of this -- every fact
 * published here already exists in an artifact Claude (or the bot's own validation/build gates) produced
 * earlier; this class only pushes, calls the GitLab API, and renders already-final documents as Markdown.
 *
 * <p><strong>A cohort's shared branch is a remediation/validation concern, not a publication one.</strong>
 * Remediation may still fast-forward several groups' commits onto one shared branch for cumulative
 * validation -- that is completely unchanged. Publication, however, always resolves ONE isolated
 * publication branch per commit: for a single-commit cohort (the overwhelmingly common case, and always
 * true for a {@code RISKY_SINGLE_GROUP} cohort), that is simply {@code cohort.branchName()} itself, exactly
 * as before. For a multi-commit cohort, every commit gets its own, freshly (re)computed, disposable local
 * branch -- the first commit's own tree is already exactly {@code base + (that group alone)} and is reused
 * directly (no cherry-pick, no re-validation: it was already validated standalone, since its own candidate
 * was cut directly from the cohort's verified SHA); every other commit's tree is reconstructed via {@code
 * git cherry-pick} onto the cohort's verified SHA and, because a clean cherry-pick only proves textual
 * mergeability -- never that the resulting tree still resolves its dependencies, builds, and passes Jenkins
 * the way the cohort's own cumulative validation did -- is independently re-validated by {@link
 * StandalonePublicationValidator} before it may ever be published. A cherry-pick conflict or a failed
 * re-validation fails closed for that ONE group only; sibling groups in the same cohort, each isolating
 * from the cohort's own verified SHA independently, are never affected either way.
 *
 * <p><strong>Never trusts {@code cohorts.json} blindly.</strong> {@link PublicationEligibility}
 * re-derives, from each commit's own {@link RemediationReport}, that dependency validation, the full
 * local build, isolated Jenkins and final integration Jenkins all genuinely succeeded before a single
 * mutating call is made -- purely per-commit, with no cohort-wide veto layered on top, so one group's own
 * failure (never even committed, so it never reaches this check) can never block an independently
 * successful sibling; {@link CohortRepositoryPreflight} independently confirms the local branch on disk
 * still matches the exact commit sequence {@code cohorts.json} recorded. Both run fresh on every
 * {@code publish}/{@code preview} call -- publication can be a separate, later step reading files a
 * {@code remediate} run wrote earlier.
 *
 * <p><strong>Discovers before it ever mutates a Merge Request's branch.</strong> Before touching a
 * group, {@link #planGroup} looks up any existing Merge Request for its own isolated publication branch by
 * stable identity (source branch name) in <em>every</em> state. An {@code OPEN} one is never pushed to
 * again (a second push would change the diff a human may already be reviewing) -- only its remote branch
 * is confirmed, read-only, to still match the expected tip; a mismatch fails closed rather than
 * force-pushing. A {@code CLOSED} or {@code MERGED} one is never pushed to, never recreated, and never
 * reopened -- the group is reported {@link RemediationCohort.PublicationStatus#MERGE_REQUEST_CLOSED} or
 * {@link RemediationCohort.PublicationStatus#MERGED} and nothing further happens for it. Only when no
 * Merge Request exists at all does this class push and create one. This is what makes a retry unable to
 * ever undo a human's decision to close or merge a Merge Request.
 *
 * <p><strong>Idempotent by construction, not by any extra bookkeeping.</strong> Every GitLab-mutating
 * call is preceded by a "does this already exist" check keyed on something stable across retries -- the
 * branch name for the Merge Request, a marker embedded in the comment body for a commit's report, a
 * marker embedded in the issue description for a Human Review group -- so re-running {@link
 * #publish(String, CohortsIndex, RemediationSummary)} after a partial failure resumes exactly where it
 * left off. A group or Human Review group whose publication fails is recorded as {@link
 * RemediationCohort.PublicationStatus#PUBLICATION_FAILED} / {@link IssuePublicationStatus#PUBLICATION_FAILED}
 * and nothing about its already-validated local commits is ever touched, reset or discarded because of it.
 *
 * <p><strong>No global, whole-run summary is ever published externally.</strong> A group's own Merge
 * Request description describes only that one group's own {@link RemediationReport} -- never an
 * aggregate of every group/cohort in the run. {@code reports/runs/<runId>/remediation-summary.json} and
 * the console summary remain purely local artifacts.
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
    private final PublicationIndexJsonRenderer publicationIndexJsonRenderer;
    private final RemoteIdentityVerifier remoteIdentityVerifier;
    private final StandalonePublicationValidator standalonePublicationValidator;
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
     * this). Standalone re-validation of a reconstructed, multi-group-cohort tree is unavailable through
     * this constructor -- see {@link StandalonePublicationValidator#unavailable()} -- since this shape is
     * also used by the standalone {@code publish} command, which has no Maven/Jenkins context of its own.
     */
    public GitLabPublicationService(
            Path repoPath,
            GitCommandRunner git,
            GitLabConfig config,
            GitLabClient gitLabClient,
            RemediationRunService runService,
            RemoteIdentityVerifier remoteIdentityVerifier) {
        this(repoPath, git, config, gitLabClient, runService, remoteIdentityVerifier,
                StandalonePublicationValidator.unavailable());
    }

    /**
     * As the six-argument constructor, but with an explicit {@link StandalonePublicationValidator} --
     * used by the immediate post-{@code remediate} publication, which already has the same Maven/Jenkins
     * context remediation itself used, so a reconstructed multi-group-cohort tree can actually be
     * re-validated rather than unconditionally refused.
     */
    public GitLabPublicationService(
            Path repoPath,
            GitCommandRunner git,
            GitLabConfig config,
            GitLabClient gitLabClient,
            RemediationRunService runService,
            RemoteIdentityVerifier remoteIdentityVerifier,
            StandalonePublicationValidator standalonePublicationValidator) {
        this(repoPath, git, config, gitLabClient, runService,
                new RemediationReportMarkdownRenderer(), new HumanReviewReportMarkdownRenderer(),
                new PublicationIndexJsonRenderer(), remoteIdentityVerifier, standalonePublicationValidator);
    }

    GitLabPublicationService(
            Path repoPath,
            GitCommandRunner git,
            GitLabConfig config,
            GitLabClient gitLabClient,
            RemediationRunService runService,
            RemediationReportMarkdownRenderer remediationReportRenderer,
            HumanReviewReportMarkdownRenderer humanReviewReportRenderer,
            PublicationIndexJsonRenderer publicationIndexJsonRenderer,
            RemoteIdentityVerifier remoteIdentityVerifier,
            StandalonePublicationValidator standalonePublicationValidator) {
        this.repoPath = Objects.requireNonNull(repoPath, "repoPath");
        this.git = Objects.requireNonNull(git, "git");
        this.config = Objects.requireNonNull(config, "config");
        this.gitLabClient = Objects.requireNonNull(gitLabClient, "gitLabClient");
        this.runService = Objects.requireNonNull(runService, "runService");
        this.remediationReportRenderer =
                Objects.requireNonNull(remediationReportRenderer, "remediationReportRenderer");
        this.humanReviewReportRenderer =
                Objects.requireNonNull(humanReviewReportRenderer, "humanReviewReportRenderer");
        this.publicationIndexJsonRenderer =
                Objects.requireNonNull(publicationIndexJsonRenderer, "publicationIndexJsonRenderer");
        this.remoteIdentityVerifier = Objects.requireNonNull(remoteIdentityVerifier, "remoteIdentityVerifier");
        this.standalonePublicationValidator =
                Objects.requireNonNull(standalonePublicationValidator, "standalonePublicationValidator");
    }

    /**
     * Every read-only check {@link #publish} would perform -- remote identity, eligibility, repository
     * preflight, and discovering any already-existing Merge Request/Issue -- rendered as a preview,
     * without a single mutating call. One run can contain several cohorts, and one cohort can contain
     * several groups: every GROUP gets its own, separately reported {@link PublicationPreview.CohortPreview}.
     */
    public PublicationPreview preview(String runId, CohortsIndex cohortsIndex, RemediationSummary summary) {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(cohortsIndex, "cohortsIndex");
        Objects.requireNonNull(summary, "summary");

        VerificationResult identity = verifyRemoteIdentity();
        List<PublicationPreview.CohortPreview> groupPreviews = new ArrayList<>();
        for (CohortsIndex.Entry cohort : cohortsIndex.cohorts()) {
            for (CohortsIndex.Commit commit : cohort.commits()) {
                if (!identity.verified()) {
                    groupPreviews.add(ineligibleGroupPreview(cohort, commit, identity.reason()));
                    continue;
                }
                groupPreviews.add(toGroupPreview(planGroup(runId, cohort, commit)));
            }
        }

        List<PublicationPreview.HumanReviewGroupPreview> humanReviewPreviews = new ArrayList<>();
        for (HumanReviewGroup group : distinctHumanReviewGroups(summary)) {
            humanReviewPreviews.add(toHumanReviewGroupPreview(runId, group, identity));
        }

        return new PublicationPreview(runId, groupPreviews, humanReviewPreviews);
    }

    /**
     * Publishes every eligible GROUP in {@code cohortsIndex} -- one per commit, never combined with a
     * sibling's, whatever cohort they shared during remediation -- and every distinct Human Review group
     * in {@code summary}, then writes {@value #PUBLICATION_FILE}. Safe to call again for the same run:
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

        List<PublicationIndex.CohortPublication> groupPublications = new ArrayList<>();
        for (CohortsIndex.Entry cohort : cohortsIndex.cohorts()) {
            for (CohortsIndex.Commit commit : cohort.commits()) {
                groupPublications.add(executeGroupPlan(planGroup(runId, cohort, commit)).publication());
            }
        }

        List<HumanReviewGroup> humanReviewGroups = distinctHumanReviewGroups(summary);
        List<PublicationIndex.HumanReviewPublication> humanReviewPublications = new ArrayList<>();
        for (HumanReviewGroup group : humanReviewGroups) {
            humanReviewPublications.add(publishHumanReviewGroup(runId, group));
        }

        return writeAndReturn(runId, new PublicationIndex(runId, groupPublications, humanReviewPublications));
    }

    private VerificationResult verifyRemoteIdentity() {
        return remoteIdentityVerifier.verify(git, repoPath, config.remoteName(), gitLabClient, config);
    }

    private PublicationIndex identityFailureIndex(
            String runId, CohortsIndex cohortsIndex, RemediationSummary summary, String reason) {
        List<PublicationIndex.CohortPublication> groups = new ArrayList<>();
        for (CohortsIndex.Entry cohort : cohortsIndex.cohorts()) {
            for (CohortsIndex.Commit commit : cohort.commits()) {
                groups.add(failedGroupResult(cohort.branchName(), cohort.verifiedSourceRef(),
                        cohort.verifiedSourceSha(), reason).publication());
            }
        }
        List<PublicationIndex.HumanReviewPublication> humanReviewGroups = distinctHumanReviewGroups(summary).stream()
                .map(group -> new PublicationIndex.HumanReviewPublication(group.groupKey(),
                        group.memberCoordinates(), IssuePublicationStatus.PUBLICATION_FAILED, null, null, reason))
                .toList();
        return new PublicationIndex(runId, groups, humanReviewGroups);
    }

    private PublicationIndex writeAndReturn(String runId, PublicationIndex index) {
        runService.writeRunArtifact(
                runService.runDirectoryFor(runId).resolve(PUBLICATION_FILE),
                publicationIndexJsonRenderer.render(index));
        return index;
    }

    // ---- planning: every read-only step, shared between preview() and publish() ---------------------

    /**
     * Everything read-only that must happen before ONE group's commit can be mutated: resolve its own
     * isolated publication branch (see this class's own javadoc), re-validate a reconstructed one when
     * required, load its own report, evaluate {@link PublicationEligibility}, run
     * {@link CohortRepositoryPreflight} against the cohort's shared history, and discover any
     * already-existing Merge Request for its own branch, in any state. Never mutates the remote --
     * {@link #preview} renders this directly; {@link #publish} additionally executes it via
     * {@link #executeGroupPlan}. Local git state (an isolated branch this method itself may create) is
     * the one exception: resolving a reconstructed tree is unavoidably a local git operation, never a
     * network one.
     */
    private GroupPlan planGroup(String runId, CohortsIndex.Entry cohort, CohortsIndex.Commit commit) {
        RemediationReport report;
        try {
            report = readRemediationReport(commit.remediationReportPath());
        } catch (RuntimeException e) {
            return GroupPlan.ineligible(cohort, commit, cohort.branchName(),
                    "could not read the Remediation Report for commit " + commit.commitSha()
                            + " (group " + commit.groupId() + "): " + e.getMessage());
        }

        EligibilityResult eligibility = PublicationEligibility.evaluate(commit, report);
        if (!eligibility.eligible()) {
            return GroupPlan.ineligible(cohort, commit, cohort.branchName(), eligibility.reason());
        }

        PreflightResult preflight = CohortRepositoryPreflight.verify(git, repoPath, cohort);
        if (!preflight.ok()) {
            return GroupPlan.ineligible(cohort, commit, cohort.branchName(), preflight.reason());
        }

        PublicationBranchResolution branch = resolvePublicationBranch(runId, cohort, commit);
        if (branch.failureReason() != null) {
            return GroupPlan.ineligible(cohort, commit, branch.branchName(), branch.failureReason());
        }

        Optional<MergeRequestRef> existing;
        try {
            existing = gitLabClient.findMergeRequestBySourceBranch(branch.branchName());
        } catch (RuntimeException e) {
            return GroupPlan.ineligible(cohort, commit, branch.branchName(),
                    "could not look up an existing merge request: " + e.getMessage());
        }

        return GroupPlan.planned(
                cohort, commit, branch.branchName(), report, branch.expectedTip(), existing.orElse(null));
    }

    /**
     * Resolves the one isolated branch/expected-tip pair {@code commit} publishes under -- see this
     * class's own javadoc for the single-commit vs. multi-commit cohort distinction. Only ever mutates
     * LOCAL git state (branch creation, checkout, cherry-pick); never pushes, never calls GitLab.
     */
    private PublicationBranchResolution resolvePublicationBranch(
            String runId, CohortsIndex.Entry cohort, CohortsIndex.Commit commit) {
        if (cohort.commits().size() == 1) {
            return PublicationBranchResolution.resolved(cohort.branchName(), commit.commitSha());
        }

        String isolatedBranch = RemediationBranchName.forPublicationIsolation(
                runId, cohort.verifiedSourceRef(), cohort.verifiedSourceSha(), commit.groupId());
        boolean isFirst = cohort.commits().get(0).equals(commit);

        String originalHead;
        try {
            originalHead = git.currentHeadSha(repoPath);
        } catch (RuntimeException e) {
            return PublicationBranchResolution.failed(isolatedBranch,
                    "could not read the repository's current checkout: " + e.getMessage());
        }

        if (git.branchExistsLocally(repoPath, isolatedBranch)) {
            git.deleteBranch(repoPath, isolatedBranch);
        }

        if (isFirst) {
            // This commit's own candidate was cut directly from the cohort's verified SHA, so its tree
            // already IS "base + (this group alone)" -- already validated standalone, no cherry-pick, no
            // re-validation. Just a fresh ref pointing directly at it.
            git.createBranch(repoPath, isolatedBranch, commit.commitSha());
            return PublicationBranchResolution.resolved(isolatedBranch, commit.commitSha());
        }

        git.createBranch(repoPath, isolatedBranch, cohort.verifiedSourceSha());
        git.checkout(repoPath, isolatedBranch);
        String isolatedTip;
        try {
            isolatedTip = git.cherryPick(repoPath, commit.commitSha());
        } catch (RuntimeException e) {
            git.abortCherryPick(repoPath);
            restoreCheckoutBestEffort(originalHead);
            return PublicationBranchResolution.failed(isolatedBranch,
                    "could not isolate this group's commit for standalone publication: cherry-pick conflict "
                            + "against the verified source ref -- this group's change may depend on another "
                            + "group's change: " + e.getMessage());
        }
        restoreCheckoutBestEffort(originalHead);

        Optional<String> revalidationFailure = standalonePublicationValidator.revalidate(
                runId, commit.groupId(), repoPath, cohort.verifiedSourceSha(), isolatedTip);
        if (revalidationFailure.isPresent()) {
            return PublicationBranchResolution.failed(isolatedBranch,
                    "this group's change could not be independently re-validated in isolation from the "
                            + "other group(s) in its cohort: " + revalidationFailure.get());
        }
        return PublicationBranchResolution.resolved(isolatedBranch, isolatedTip);
    }

    private void restoreCheckoutBestEffort(String originalHead) {
        try {
            git.checkout(repoPath, originalHead);
        } catch (RuntimeException e) {
            // Best-effort only -- see MavenAndJenkinsStandalonePublicationValidator's identical reasoning.
        }
    }

    private record PublicationBranchResolution(String branchName, String expectedTip, String failureReason) {
        static PublicationBranchResolution resolved(String branchName, String expectedTip) {
            return new PublicationBranchResolution(branchName, expectedTip, null);
        }

        static PublicationBranchResolution failed(String branchName, String reason) {
            return new PublicationBranchResolution(branchName, null, reason);
        }
    }

    /**
     * Carries out exactly the policy required for each of a discovered Merge Request's possible states
     * (or its absence) -- see this class's own javadoc for the full rationale. Operates on exactly ONE
     * group's own isolated branch; a failure here never touches a sibling group's own plan/execution.
     */
    private GroupResult executeGroupPlan(GroupPlan plan) {
        if (!plan.eligible()) {
            return failedGroupResult(
                    plan.branchName(), plan.cohort().verifiedSourceRef(), plan.cohort().verifiedSourceSha(),
                    plan.ineligibleReason());
        }

        try {
            MergeRequestRef existing = plan.existingMergeRequest();
            if (existing == null) {
                pushAndVerify(plan.branchName(), plan.expectedTip());
                MergeRequestRef created = gitLabClient.createMergeRequest(
                        plan.branchName(), targetBranchFor(plan.cohort().verifiedSourceRef()),
                        mergeRequestTitle(plan), mergeRequestDescription(plan.report()));
                return publishCommitAndFinish(plan, created, RemediationCohort.PublicationStatus.MERGE_REQUEST_OPENED);
            }

            return switch (existing.state()) {
                case OPEN -> {
                    String remoteSha = git.lsRemoteSha(repoPath, config.remoteName(), plan.branchName());
                    if (!plan.expectedTip().equals(remoteSha)) {
                        yield failedGroupResult(plan.branchName(), plan.cohort().verifiedSourceRef(),
                                plan.cohort().verifiedSourceSha(),
                                "remote branch " + plan.branchName() + " does not match the expected tip "
                                        + "(expected " + plan.expectedTip() + ", remote has " + remoteSha
                                        + ") -- an open Merge Request already exists, so this is never force-pushed");
                    }
                    yield publishCommitAndFinish(
                            plan, existing, RemediationCohort.PublicationStatus.MERGE_REQUEST_OPENED);
                }
                case CLOSED -> terminalDiscoveredState(plan, existing, RemediationCohort.PublicationStatus.MERGE_REQUEST_CLOSED);
                case MERGED -> terminalDiscoveredState(plan, existing, RemediationCohort.PublicationStatus.MERGED);
            };
        } catch (RuntimeException e) {
            return failedGroupResult(plan.branchName(), plan.cohort().verifiedSourceRef(),
                    plan.cohort().verifiedSourceSha(), e.getMessage());
        }
    }

    /**
     * A Merge Request was discovered CLOSED or MERGED: no push, no branch recreation, no reopening, no
     * new Merge Request, and -- deliberately -- no commit report posted either, so a retry never looks
     * like fresh activity on an object a human has already closed or merged.
     */
    private GroupResult terminalDiscoveredState(
            GroupPlan plan, MergeRequestRef existing, RemediationCohort.PublicationStatus status) {
        return new GroupResult(new PublicationIndex.CohortPublication(
                plan.branchName(), plan.cohort().verifiedSourceRef(), plan.cohort().verifiedSourceSha(), status,
                existing.webUrl(), existing.iid(), List.of(), null));
    }

    /**
     * Pushes the group's own isolated branch -- only ever reached when no Merge Request exists for it
     * yet -- and confirms, read-only, that the remote now genuinely carries the expected tip.
     */
    private void pushAndVerify(String branchName, String expectedTip) {
        if (!branchName.startsWith(REMEDIATION_BRANCH_NAMESPACE)) {
            throw new GitLabPublicationException(
                    "refusing to push a branch outside the " + REMEDIATION_BRANCH_NAMESPACE + " namespace: "
                            + branchName);
        }
        git.push(repoPath, config.remoteName(), branchName);
        String remoteSha = git.lsRemoteSha(repoPath, config.remoteName(), branchName);
        if (!expectedTip.equals(remoteSha)) {
            throw new GitLabPublicationException("push to " + branchName + " completed, but the "
                    + "remote tip (" + remoteSha + ") does not match the expected tip (" + expectedTip + ")");
        }
    }

    private GroupResult publishCommitAndFinish(
            GroupPlan plan, MergeRequestRef mergeRequest, RemediationCohort.PublicationStatus status) {
        publishCommitReport(plan.expectedTip(), plan.commit(), plan.report());
        PublicationIndex.PublishedCommit publishedCommit =
                new PublicationIndex.PublishedCommit(plan.commit().groupId(), plan.expectedTip(), true);
        PublicationIndex.CohortPublication publication = new PublicationIndex.CohortPublication(
                plan.branchName(), plan.cohort().verifiedSourceRef(), plan.cohort().verifiedSourceSha(), status,
                mergeRequest.webUrl(), mergeRequest.iid(), List.of(publishedCommit), null);
        return new GroupResult(publication);
    }

    private GroupResult failedGroupResult(
            String branchName, String verifiedSourceRef, String verifiedSourceSha, String reason) {
        return new GroupResult(new PublicationIndex.CohortPublication(
                branchName, verifiedSourceRef, verifiedSourceSha,
                RemediationCohort.PublicationStatus.PUBLICATION_FAILED, null, null, List.of(), reason));
    }

    private record GroupResult(PublicationIndex.CohortPublication publication) {
    }

    /**
     * What planning learned about one group's commit, before anything is executed. {@code report} and
     * {@code expectedTip} are populated only when {@code eligible}; {@code existingMergeRequest} is
     * {@code null} both when ineligible and when genuinely no Merge Request exists yet -- callers tell
     * the two apart via {@code eligible}. {@code branchName} is always populated -- the group's own
     * isolated publication branch, whether or not planning past that point succeeded -- so an ineligible
     * result can still be reported against the right branch name.
     */
    private record GroupPlan(
            CohortsIndex.Entry cohort,
            CohortsIndex.Commit commit,
            String branchName,
            boolean eligible,
            String ineligibleReason,
            RemediationReport report,
            String expectedTip,
            MergeRequestRef existingMergeRequest) {

        static GroupPlan ineligible(
                CohortsIndex.Entry cohort, CohortsIndex.Commit commit, String branchName, String reason) {
            return new GroupPlan(cohort, commit, branchName, false, reason, null, null, null);
        }

        static GroupPlan planned(
                CohortsIndex.Entry cohort, CohortsIndex.Commit commit, String branchName, RemediationReport report,
                String expectedTip, MergeRequestRef existingMergeRequest) {
            return new GroupPlan(cohort, commit, branchName, true, null, report, expectedTip, existingMergeRequest);
        }
    }

    private PublicationPreview.CohortPreview toGroupPreview(GroupPlan plan) {
        MergeRequestRef existing = plan.existingMergeRequest();
        return new PublicationPreview.CohortPreview(
                plan.cohort().verifiedSourceRef(), plan.cohort().verifiedSourceSha(), plan.branchName(),
                plan.branchName(), plan.eligible() ? plan.expectedTip() : null,
                targetBranchFor(plan.cohort().verifiedSourceRef()),
                List.of(plan.commit().groupId()), List.of(plan.commit().commitSha()),
                plan.eligible(), plan.ineligibleReason(),
                existing == null ? null : existing.state(), existing == null ? null : existing.webUrl());
    }

    private PublicationPreview.CohortPreview ineligibleGroupPreview(
            CohortsIndex.Entry cohort, CohortsIndex.Commit commit, String reason) {
        return new PublicationPreview.CohortPreview(
                cohort.verifiedSourceRef(), cohort.verifiedSourceSha(), cohort.branchName(), cohort.branchName(),
                null, targetBranchFor(cohort.verifiedSourceRef()),
                List.of(commit.groupId()), List.of(commit.commitSha()),
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

    /** Posts the commit's own report, unless a retry finds it was already posted. Posted against
     *  {@code publishedSha} -- the actually-pushed commit (the cherry-picked commit's own new SHA for a
     *  reconstructed tree; {@code commit.commitSha()} itself otherwise) -- never assumed to equal
     *  {@code commit.commitSha()} in the reconstructed case. */
    private void publishCommitReport(String publishedSha, CohortsIndex.Commit commit, RemediationReport report) {
        String marker = commitReportMarker(publishedSha);
        if (gitLabClient.commitCommentContains(publishedSha, marker)) {
            return;
        }
        String body = marker + "\n\n" + remediationReportRenderer.render(report);
        gitLabClient.postCommitComment(publishedSha, body);
    }

    /** ONE group's own report content, and nothing else -- never a whole-run or whole-cohort aggregate. */
    private String mergeRequestDescription(RemediationReport report) {
        return remediationReportRenderer.render(report);
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

    /**
     * One group, one title -- never a "N groups" pluralization, since a Merge Request is now always about
     * exactly one group. Carries a {@code [Risky]} prefix for a {@code RISKY_SINGLE_GROUP} cohort, and a
     * {@code [Needs review: plan scope extended]} prefix when {@code PlanConformanceGate} only accepted
     * this commit via a narrow, failure-driven scope extension (see {@code CohortsIndex.Commit
     * #requiresHumanReviewDespiteConformance()}) -- either way, a human reviewing this title sees
     * immediately that ordinary auto-merge expectations do not apply.
     */
    private static String mergeRequestTitle(GroupPlan plan) {
        StringBuilder title = new StringBuilder();
        if (plan.cohort().effectiveKind() == RemediationCohort.CohortKind.RISKY_SINGLE_GROUP) {
            title.append("[Risky] ");
        }
        if (plan.commit().requiresHumanReviewDespiteConformance()) {
            title.append("[Needs review: plan scope extended] ");
        }
        title.append("Dependency remediation: ").append(plan.commit().groupId())
                .append(" (").append(plan.branchName()).append(')');
        return title.toString();
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
