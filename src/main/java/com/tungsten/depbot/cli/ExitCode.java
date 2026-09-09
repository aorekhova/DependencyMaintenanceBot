package com.tungsten.depbot.cli;

/**
 * Every process outcome this CLI can produce, with the integer status it returns.
 *
 * <p>Exit code {@code 0} means the scan ran to completion. It does <em>not</em> mean the
 * project is free of vulnerabilities; the security verdict is reported separately on the
 * console. CI gating on severity is deliberately out of scope for this slice.
 */
public enum ExitCode {

    SUCCESS(0),
    USAGE_ERROR(1),
    CONFIG_ERROR(2),
    API_ERROR(3),
    NETWORK_ERROR(4),
    MALFORMED_RESPONSE(5),

    /**
     * The scan itself succeeded but the report files could not be written.
     *
     * <p>Kept distinct from the codes above because the diagnosis is entirely different: Mend was
     * reached and its response understood, so pointing an operator at Mend would waste their time.
     * Kept distinct from {@link #UNEXPECTED_ERROR} because a full disk, a read-only workspace or a
     * file locked by antivirus is an expected environmental condition rather than a defect.
     *
     * <p>Not folded into {@link #SUCCESS} because the JSON report is the input to downstream
     * automation: exiting zero with a missing report would let another system silently consume stale
     * or absent data, which is the hardest kind of failure to trace back.
     */
    REPORT_WRITE_ERROR(6),

    /**
     * A command could not find or understand a local report file it reads as input: either
     * {@code plan-remediation} reading {@code reports/mend-actionable-vulnerabilities.json}
     * (written by {@code scan}), or {@code prepare-remediation-branches} reading
     * {@code reports/remediation-plan.json} (written by {@code plan-remediation}). Also used for a
     * well-formed {@code remediate --dependency groupId:artifactId} whose coordinates do not match
     * any library the plan can turn into a remediation unit -- the plan itself was read and
     * understood just fine, but does not contain what was asked for.
     *
     * <p>Kept distinct from {@link #MALFORMED_RESPONSE} because that one is about a live Mend API
     * response; this one is about a local file an earlier command should have produced. The fix is
     * almost always to run that earlier command first.
     */
    REMEDIATION_SOURCE_ERROR(7),

    /**
     * A {@code git} command failed or could not be run at all, at any point where a mechanical git
     * problem means the checkout can no longer be trusted to continue on its own: {@code fetch} or
     * {@code rev-parse} against the shared base commit or a branch name collision in
     * {@code prepare-remediation-branches}; a dirty checkout (or a merge/rebase/cherry-pick left
     * mid-flight) refusing to start {@code remediate}'s execution stage; a checkout switch, staging,
     * commit or rollback itself failing partway through that stage; or the checkout being unable to
     * safely return to its original branch afterward.
     *
     * <p>Kept distinct from {@link #CONFIG_ERROR} (a missing or invalid {@code WEBAPP_REPO_PATH})
     * and from {@link #REMEDIATION_SOURCE_ERROR} (a missing or unreadable local report): this one
     * means the repository itself rejected an operation or was not in a state safe to touch.
     */
    GIT_OPERATION_ERROR(8),

    /**
     * The git-level machinery is fine -- branches were created, the checkout was restored -- but at
     * least one remediation unit was rolled back: Claude Code did not finish cleanly (exited
     * non-zero, timed out, or could not be started at all), or its change failed the diff-policy
     * check.
     *
     * <p>Not folded into {@link #SUCCESS} because the units that did commit are only
     * {@code COMMITTED_PENDING_VALIDATION}, not a finished, verified upgrade; exiting zero would let
     * an operator assume every library was handled. Kept distinct from {@link #GIT_OPERATION_ERROR}
     * because the branches and checkout were handled correctly -- it is a specific unit's change
     * that did not qualify to keep.
     */
    REMEDIATION_EXECUTION_ERROR(9),

    /**
     * Nothing went wrong mechanically, but at least one library is waiting on a person for a reason that
     * is not simply "please review this": the assessment judged the change unsafe to automate
     * ({@link com.tungsten.depbot.assessment.AutomationSafety#HUMAN_REVIEW_REQUIRED}), could not establish
     * what it needed, named a ref that does not exist, the implementation stopped or was refused by the
     * local gate, or a committed change failed the mandatory full build.
     *
     * <p>Kept distinct from {@link #REMEDIATION_EXECUTION_ERROR} because there is nothing to retry and
     * nothing broken -- the bot did exactly what it should and handed the decision over. Kept distinct
     * from {@link #SUCCESS} because a run that changed nothing must not look like a run that fixed
     * everything. Kept distinct from {@link #HUMAN_REVIEW_REQUIRED}: this code means no safe remediation
     * plan could be established or trusted at all -- that one means a safe plan exists, a person just has
     * to authorise it.
     */
    MANUAL_REMEDIATION_REQUIRED(10),

    /**
     * Nothing went wrong and no library needs manual remediation work -- but at least one remediation
     * group was judged {@link com.tungsten.depbot.assessment.AutomationSafety#HUMAN_REVIEW_REQUIRED}: no
     * implementation call ran and nothing about the repository was changed, but the read-only Human
     * Review Engineer prepared a report -- what is vulnerable, why, what would fix it, how to validate --
     * for a person to act on.
     *
     * <p>Kept distinct from {@link #MANUAL_REMEDIATION_REQUIRED} on purpose: that code means no safe plan
     * could be established or trusted at all; this one means a safe plan exists and is fully described in
     * the Human Review Report, a person just has to authorise carrying it out -- the bot never does so
     * unattended. Collapsing the two into one code would hide from an external orchestrator (CI, Jenkins,
     * a script polling this process's exit status) exactly the distinction that matters most: whether
     * there is analysis left to do, or only a decision to make. Not folded into {@link #SUCCESS} either,
     * since a run with an unactioned Human Review Report is not "nothing left to do."
     */
    HUMAN_REVIEW_REQUIRED(11),

    /**
     * {@code publish} could not find or understand the named run's persisted {@code cohorts.json}/
     * {@code remediation-summary.json} -- almost always because the run id does not exist, or {@code
     * remediate} never reached the point of writing them.
     *
     * <p>Kept distinct from {@link #REMEDIATION_SOURCE_ERROR}: that one is about {@code remediate}'s own
     * input report; this one is about a previous {@code remediate} run's own output, read back for a
     * separate, later publication step.
     */
    PUBLICATION_SOURCE_ERROR(12),

    /**
     * {@code publish} ran, but at least one cohort or Human Review group did not publish successfully --
     * a push, a Merge Request, an Issue, or a per-commit report failed, or a remote branch no longer
     * matched what was expected. Every already-validated local commit is untouched either way: this code
     * means only that GitLab publication itself did not fully complete, never that remediation or
     * validation failed. See {@link com.tungsten.depbot.remediation.RemediationCohort.PublicationStatus
     * #PUBLICATION_FAILED}.
     */
    PUBLICATION_FAILED(13),

    UNEXPECTED_ERROR(70);

    private final int value;

    ExitCode(int value) {
        this.value = value;
    }

    public int value() {
        return value;
    }
}
