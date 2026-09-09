package com.tungsten.depbot.remediation;

import java.util.List;
import java.util.Objects;

/**
 * The run-wide {@code cohorts.json} index: for every {@link RemediationCohort} that actually produced
 * at least one commit, its shared branch, its verified target ref/SHA, and the commit &harr; group
 * &harr; {@link RemediationReport} correspondence for each of its successful commits, in commit order.
 *
 * <p>Purely an internal, local index -- see {@code VulnerabilityRemediationService}'s own class javadoc
 * on {@link RemediationCohort.PublicationStatus} for why this is never the same thing as a report being
 * attached to a commit inside a GitLab Merge Request. A cohort whose every group failed or was rolled
 * back is left out of {@link #cohorts()} entirely: there is no branch content worth indexing, and a
 * failed group must never be made to look like a published commit here.
 */
public record CohortsIndex(String runId, List<Entry> cohorts) {

    public CohortsIndex {
        Objects.requireNonNull(runId, "runId");
        cohorts = cohorts == null ? List.of() : List.copyOf(cohorts);
    }

    /** One cohort: its shared branch, its verified target, and its successful commits in order. */
    public record Entry(
            String branchName,
            String verifiedSourceRef,
            String verifiedSourceSha,
            RemediationCohort.PublicationStatus publicationStatus,
            List<Commit> commits,
            RemediationCohort.CohortKind cohortKind) {

        public Entry {
            Objects.requireNonNull(branchName, "branchName");
            Objects.requireNonNull(verifiedSourceRef, "verifiedSourceRef");
            Objects.requireNonNull(verifiedSourceSha, "verifiedSourceSha");
            Objects.requireNonNull(publicationStatus, "publicationStatus");
            if (commits == null || commits.isEmpty()) {
                throw new IllegalArgumentException("a cohort entry must have at least one commit");
            }
            commits = List.copyOf(commits);
        }

        /** Legacy 5-arg constructor -- every pre-existing caller/reader produces/reads an ordinary cohort. */
        public Entry(
                String branchName, String verifiedSourceRef, String verifiedSourceSha,
                RemediationCohort.PublicationStatus publicationStatus, List<Commit> commits) {
            this(branchName, verifiedSourceRef, verifiedSourceSha, publicationStatus, commits, null);
        }

        /** {@code cohortKind} is {@code null} for every run persisted before this field existed. */
        public RemediationCohort.CohortKind effectiveKind() {
            return cohortKind == null ? RemediationCohort.CohortKind.ORDINARY : cohortKind;
        }
    }

    /** One group's successful commit, and where its own {@link RemediationReport} was written. */
    public record Commit(String groupId, String commitSha, String remediationReportPath) {

        public Commit {
            Objects.requireNonNull(groupId, "groupId");
            Objects.requireNonNull(commitSha, "commitSha");
            Objects.requireNonNull(remediationReportPath, "remediationReportPath");
        }
    }
}
