package com.tungsten.depbot.publication;

import com.tungsten.depbot.remediation.RemediationCohort;

import java.util.List;
import java.util.Objects;

/**
 * The run-wide {@code publication.json}: what {@code GitLabPublicationService} actually did with every
 * cohort and every Human Review group, and the real GitLab identifiers it got back.
 *
 * <p>Deliberately a supplement to {@code cohorts.json}, never a replacement for it -- {@code
 * cohorts.json} already answers "which commit belongs to which group, and where its own {@code
 * RemediationReport} is." This file answers the next question, "what did GitLab do with that": the
 * pushed branch's Merge Request, whether each commit's report actually reached it, and the Issue each
 * Human Review group got instead of a commit. {@link CohortPublication#branchName()} is the key back
 * into {@code cohorts.json}'s own {@code branchName} -- the two files are never merged into one, so
 * neither has to change shape when the other does.
 */
public record PublicationIndex(
        String runId, List<CohortPublication> cohorts, List<HumanReviewPublication> humanReviewGroups) {

    public PublicationIndex {
        Objects.requireNonNull(runId, "runId");
        cohorts = cohorts == null ? List.of() : List.copyOf(cohorts);
        humanReviewGroups = humanReviewGroups == null ? List.of() : List.copyOf(humanReviewGroups);
    }

    /** One cohort's publication outcome -- keyed by {@code branchName}, matching {@code cohorts.json}. */
    public record CohortPublication(
            String branchName,
            String verifiedSourceRef,
            String verifiedSourceSha,
            RemediationCohort.PublicationStatus status,
            String mergeRequestUrl,
            Integer mergeRequestIid,
            List<PublishedCommit> publishedCommits,
            String errorMessage) {

        public CohortPublication {
            Objects.requireNonNull(branchName, "branchName");
            Objects.requireNonNull(verifiedSourceRef, "verifiedSourceRef");
            Objects.requireNonNull(verifiedSourceSha, "verifiedSourceSha");
            Objects.requireNonNull(status, "status");
            publishedCommits = publishedCommits == null ? List.of() : List.copyOf(publishedCommits);
        }
    }

    /** Whether one specific commit's own {@code RemediationReport} reached GitLab as a commit comment. */
    public record PublishedCommit(String groupId, String commitSha, boolean reportPublished) {

        public PublishedCommit {
            Objects.requireNonNull(groupId, "groupId");
            Objects.requireNonNull(commitSha, "commitSha");
        }
    }

    /**
     * One Human Review group's Issue -- {@code groupKey} is an internal, stable identifier (the group's
     * own unit id) used only to find the Issue again on a retry; it is never shown to a person.
     */
    public record HumanReviewPublication(
            String groupKey,
            List<String> memberCoordinates,
            IssuePublicationStatus status,
            String issueUrl,
            Integer issueIid,
            String errorMessage) {

        public HumanReviewPublication {
            Objects.requireNonNull(groupKey, "groupKey");
            Objects.requireNonNull(status, "status");
            memberCoordinates = memberCoordinates == null ? List.of() : List.copyOf(memberCoordinates);
        }
    }
}
