package com.tungsten.depbot.publication;

import java.util.List;
import java.util.Objects;

/**
 * Every read-only fact {@link GitLabPublicationService#publish} would act on, rendered without a single
 * mutating call -- what {@code publish --run &lt;id&gt; --dry-run} shows. Multi-cohort by design: one run
 * can contain several cohorts (different verified source refs/SHAs), and each gets its own {@link
 * CohortPreview}, never collapsed into one run-wide branch/target/tip.
 */
public record PublicationPreview(
        String runId, List<CohortPreview> cohorts, List<HumanReviewGroupPreview> humanReviewGroups) {

    public PublicationPreview {
        Objects.requireNonNull(runId, "runId");
        cohorts = cohorts == null ? List.of() : List.copyOf(cohorts);
        humanReviewGroups = humanReviewGroups == null ? List.of() : List.copyOf(humanReviewGroups);
    }

    /**
     * One cohort's own preview. {@code expectedHeadSha} is {@code null} exactly when {@code eligible} is
     * {@code false} -- an ineligible cohort was never pushed to in reality, so there is no tip to expect.
     * {@code existingMergeRequestState}/{@code existingMergeRequestUrl} are both {@code null} when no
     * Merge Request exists yet for this cohort's branch (one would be created); otherwise they name
     * exactly what {@link GitLabClient#findMergeRequestBySourceBranch} discovered, in whatever state.
     */
    public record CohortPreview(
            String sourceRef,
            String sourceSha,
            String localBranch,
            String remoteBranch,
            String expectedHeadSha,
            String targetBranch,
            List<String> groupIds,
            List<String> commitShas,
            boolean eligible,
            String ineligibleReason,
            MergeRequestState existingMergeRequestState,
            String existingMergeRequestUrl) {

        public CohortPreview {
            Objects.requireNonNull(sourceRef, "sourceRef");
            Objects.requireNonNull(sourceSha, "sourceSha");
            Objects.requireNonNull(localBranch, "localBranch");
            groupIds = groupIds == null ? List.of() : List.copyOf(groupIds);
            commitShas = commitShas == null ? List.of() : List.copyOf(commitShas);
        }
    }

    /**
     * One Human Review group's own preview. {@code existingIssueState}/{@code existingIssueUrl} are both
     * {@code null} when no Issue exists yet for this group's stable identity (one would be created).
     */
    public record HumanReviewGroupPreview(
            String groupKey, List<String> memberCoordinates, IssueState existingIssueState, String existingIssueUrl) {

        public HumanReviewGroupPreview {
            Objects.requireNonNull(groupKey, "groupKey");
            memberCoordinates = memberCoordinates == null ? List.of() : List.copyOf(memberCoordinates);
        }
    }
}
