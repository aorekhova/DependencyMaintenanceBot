package com.tungsten.depbot.remediation;

import java.util.List;
import java.util.Objects;

/**
 * Every automatically-allowed remediation group in a run that shares one verified source ref, and
 * therefore one shared branch.
 *
 * <p>Source ref is the boundary of what may share a branch, not just source SHA: two different target
 * refs can temporarily resolve to the same commit, but they are still two different future Merge
 * Request targets, so they must never collapse into one cohort just because
 * {@code verifiedSourceSha} happens to match today. {@link CohortKey} is keyed on both fields together
 * for exactly this reason -- see {@code VulnerabilityRemediationService}, which partitions validated
 * groups into cohorts by that pair, never by SHA alone.
 *
 * <p>{@code branchName} is created once per cohort and every group in {@code groups} lands on it as its
 * own single commit, in sequence -- the first group's baseline is {@code verifiedSourceSha}, each
 * later group's baseline is wherever the previous one left the branch's tip.
 */
public record RemediationCohort(
        String verifiedSourceRef,
        String verifiedSourceSha,
        String branchName,
        List<RemediationGroup> groups,
        CohortKind kind) {

    public RemediationCohort {
        Objects.requireNonNull(verifiedSourceRef, "verifiedSourceRef");
        Objects.requireNonNull(verifiedSourceSha, "verifiedSourceSha");
        Objects.requireNonNull(branchName, "branchName");
        if (groups == null || groups.isEmpty()) {
            throw new IllegalArgumentException("a remediation cohort must have at least one group");
        }
        groups = List.copyOf(groups);
        kind = kind == null ? CohortKind.ORDINARY : kind;
    }

    /** Legacy 4-arg constructor -- every pre-existing caller builds an ordinary, multi-group cohort. */
    public RemediationCohort(
            String verifiedSourceRef, String verifiedSourceSha, String branchName, List<RemediationGroup> groups) {
        this(verifiedSourceRef, verifiedSourceSha, branchName, groups, CohortKind.ORDINARY);
    }

    /**
     * What kind of cohort this is -- {@link #ORDINARY} (the shared, multi-group cumulative branch every
     * {@code AUTOMATIC_ALLOWED} group has always used) or {@link #RISKY_SINGLE_GROUP} (a
     * {@code HUMAN_REVIEW_REQUIRED} group given its own isolated attempt: always exactly one group, its
     * own branch, and -- if it succeeds -- its own dedicated, always-human-review Merge Request, never
     * combined with any other group).
     */
    public enum CohortKind {
        ORDINARY,
        RISKY_SINGLE_GROUP
    }

    /**
     * What a cohort's branch has become in GitLab. {@code GitLabPublicationService} (the {@code
     * publication} package) is what actually drives a cohort through {@link #PUSHED} and {@link
     * #MERGE_REQUEST_OPENED} -- {@code VulnerabilityRemediationService} itself only ever produces
     * {@link #READY_TO_PUBLISH}, the end of the purely local pipeline. {@link #MERGED} is reserved and
     * never produced automatically by anything in this application -- a human merges, always.
     */
    public enum PublicationStatus {
        /** Every group in the cohort has been attempted; the branch exists locally with its commits. */
        READY_TO_PUBLISH,
        /** The branch has been pushed to the remote. An intermediate state on the way to a Merge Request. */
        PUSHED,
        /**
         * A Merge Request exists (found already open, or newly created) targeting the verified source
         * ref, with every successful commit's own {@code RemediationReport} published against its SHA.
         * This is the "publication succeeded" state -- what a caller means by "published."
         */
        MERGE_REQUEST_OPENED,
        /**
         * A Merge Request with this cohort's stable identity already exists and is CLOSED. The bot never
         * reopens a human-closed Merge Request automatically, never pushes to its branch again (which
         * could otherwise resurrect a branch GitLab deleted when the Merge Request was closed), and
         * never posts commit reports against it -- retrying a closed Merge Request must never look like
         * fresh activity on it. This status exists so {@code publication.json}/console output can say so
         * plainly, distinct from both {@link #MERGE_REQUEST_OPENED} (would wrongly imply it is open) and
         * {@link #PUBLICATION_FAILED} (nothing failed here; only the Merge Request itself needs a human
         * decision).
         */
        MERGE_REQUEST_CLOSED,
        /**
         * A Merge Request with this cohort's stable identity already exists and is MERGED -- reserved as
         * a value this application can only ever <em>discover</em>, never produce by its own action: a
         * human merges, always. Discovering one is the strongest possible signal to stop -- no push, no
         * new Merge Request, and no attempt to recreate a branch GitLab has likely already deleted.
         */
        MERGED,
        /**
         * Publication for this cohort did not complete -- the push, the Merge Request, or a per-commit
         * report failed. The cohort's own local commits are untouched either way: a publication failure
         * never resets, rewrites or discards already-validated work.
         */
        PUBLICATION_FAILED
    }

    /** Ties a cohort to its target ref/SHA pair, so it is never merged with another cohort by mistake. */
    public record CohortKey(String verifiedSourceRef, String verifiedSourceSha) {
        public CohortKey {
            Objects.requireNonNull(verifiedSourceRef, "verifiedSourceRef");
            Objects.requireNonNull(verifiedSourceSha, "verifiedSourceSha");
        }
    }
}
