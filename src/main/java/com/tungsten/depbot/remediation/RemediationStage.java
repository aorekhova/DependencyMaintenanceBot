package com.tungsten.depbot.remediation;

/**
 * How far one library's remediation got. Recorded so a library that produced no commit can always say
 * which gate stopped it, rather than leaving that to be reconstructed from several artifacts.
 */
public enum RemediationStage {

    /**
     * Remote refs could not be brought up to date, so nothing ran at all.
     *
     * <p>The run stops here rather than assessing against a possibly-stale view of the remote. The whole
     * point of the assessment is to find which branch a finding really belongs to, and a set of refs that
     * may be missing the release or hotfix line it lives on cannot support that conclusion -- an
     * assessment would be at risk of reporting "not present anywhere" about a branch it never had.
     */
    REMOTE_REFS_REFRESH,

    /**
     * Remote refs were current, but the managed checkout could not be reset to the verified tip of its
     * own remote counterpart -- so nothing in this batch was investigated, to avoid reasoning about a
     * possibly stale snapshot of the repository.
     */
    REPOSITORY_REFRESH,

    /** The batch analysis ran, but this finding's own verdict did not authorise an implementation. */
    ASSESSMENT,

    /**
     * The whole-batch Vulnerability Analysis this finding was part of never produced a coverage-complete,
     * routable result -- see {@code BatchAnalysisStatus#INCOMPLETE}. Distinct from {@link #ASSESSMENT}:
     * that stage means the analysis reached a real verdict for this finding, just not one authorising
     * implementation; this one means no per-finding verdict was ever trustworthy enough to route at all.
     */
    ASSESSMENT_INCOMPLETE,

    /** The analysis authorised work for this finding's group, but the ref it named could not be
     * confirmed through git. */
    SOURCE_REF_VERIFICATION,

    /**
     * This finding's remediation group could not be trusted -- {@code RemediationGroupValidator} found
     * that the group Claude proposed did not check out against the batch's real findings (most often, a
     * member coordinate naming something not actually in this run).
     */
    GROUPING,

    /** The ref was confirmed, but the remediation branch could not be created or checked out. */
    BRANCH_PREPARATION,

    /** The implementation call ran. Whether its work was kept is a separate question. */
    IMPLEMENTATION,

    /**
     * A read-only Human Review Engineer call ran for this finding or its group -- either instead of
     * Implementation (a group never authorised for automation, or an ungrouped finding), or after it,
     * when an automatic group's own Remediation Engineer attempt did not end in a committed change.
     */
    HUMAN_REVIEW
}
