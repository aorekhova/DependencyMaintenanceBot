package com.tungsten.depbot.implementation;

import com.tungsten.depbot.assessment.AnalysisRemediationGroup;
import com.tungsten.depbot.assessment.PartialAnalysisState;
import com.tungsten.depbot.assessment.VulnerabilityWorkItem;
import com.tungsten.depbot.report.Severity;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/**
 * Everything the implementation call needs: one or more findings and their own conclusions, the shared
 * remediation plan the analysis decided for the group as a whole, and the branch the orchestrator
 * prepared for it.
 *
 * <p>{@code members} is a list rather than a single finding because every implementation call operates
 * on a <em>remediation group</em> (see {@code RemediationGroup}), and the overwhelmingly common case --
 * one unrelated finding -- is simply a group of one. There is deliberately no separate single-finding
 * code path: a group of one and a group of several are implemented, validated, committed and built the
 * same way, through the same call. {@code group} carries what the analysis decided for the group as a
 * whole -- its plan, its source ref, its automation-safety decision -- since remediation now happens per
 * group, not per finding; each member's own {@link ImplementationGroupMember#findingAssessment()} carries
 * only what is genuinely specific to that one finding.
 *
 * <p>{@code companionCoordinates} are coordinates the analysis named as required alongside this group
 * that carry no Mend finding of their own -- still part of what the implementation is told to consider,
 * since the whole reason they were named was that the fix is incomplete without them.
 *
 * <p>{@code branchName} and {@code branchBaseSha} describe the shared branch this run's automatic
 * remediation groups for one verified source ref land on, one commit per group, in sequence --
 * {@code branchName} is constant across every group sharing that branch; {@code branchBaseSha} is
 * wherever the previous group in the same sequence left the branch's tip (or the cohort's own verified
 * commit, for the first group), never a SHA any analysis supplied.
 *
 * <p>{@code priority} and {@code executionOrder} are the group's own, Java-computed cumulative-execution
 * facts (see {@code GroupPriority}/{@code RemediationGroup}) -- carried here purely so the finalization
 * evidence (see {@code RemediationImplementationService}) and any Human Review report built for this
 * group can cite them without a second lookup.
 *
 * <p>{@code partialAnalysisState} is {@code null} for every ordinary group -- one whose plan came from a
 * genuinely completed {@link com.tungsten.depbot.assessment.BatchAnalysis}. It is non-null only for the
 * partial-analysis fallback (see {@code VulnerabilityRemediationService}), when Vulnerability Analysis
 * could not complete after two attempts: its presence is what tells {@link ImplementationPromptRenderer}
 * to render the constrained fallback prompt instead of the ordinary one, since there is no real
 * engineered plan here for the ordinary prompt to reproduce -- only whatever partial evidence the two
 * analysis attempts left behind, and Mend's own raw finding data.
 *
 * <p>{@code repairContext} is {@code null} for attempt 1 of every group. It is non-null only for attempt
 * 2 -- the one-and-only repair attempt, run by the same Remediation Engineer after attempt 1 failed --
 * and carries the diff, the failed stage and whatever evidence that stage produced, which
 * {@link ImplementationPromptRenderer} renders as an explicit instruction to fix that specific problem
 * rather than re-investigate or change direction. {@code attemptNumber} is which implementation attempt
 * this is for the group (1 = initial, 2 = the one-and-only repair attempt) -- purely descriptive
 * bookkeeping carried here so artifact paths/reports can cite it without a second lookup.
 */
public record ImplementationContext(
        String runId,
        String unitId,
        Path workspace,
        String branchName,
        String branchBaseSha,
        String verifiedSourceRef,
        AnalysisRemediationGroup group,
        List<ImplementationGroupMember> members,
        List<String> companionCoordinates,
        Severity priority,
        int executionOrder,
        PartialAnalysisState partialAnalysisState,
        RepairContext repairContext,
        int attemptNumber) {

    public ImplementationContext {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(unitId, "unitId");
        Objects.requireNonNull(workspace, "workspace");
        Objects.requireNonNull(branchName, "branchName");
        Objects.requireNonNull(branchBaseSha, "branchBaseSha");
        Objects.requireNonNull(group, "group");
        Objects.requireNonNull(priority, "priority");
        if (members == null || members.isEmpty()) {
            throw new IllegalArgumentException("an implementation context must have at least one member");
        }
        members = List.copyOf(members);
        companionCoordinates = companionCoordinates == null ? List.of() : List.copyOf(companionCoordinates);
    }

    /**
     * Backward-compatible shape from before priority/executionOrder existed -- defaults them to
     * {@link Severity#OTHER}/{@code 0}, and {@code partialAnalysisState}/{@code approvedPlan} to
     * {@code null} (the ordinary case), {@code attemptNumber} to {@code 1} (the initial attempt). Kept so
     * every existing caller that never cared about cumulative ordering (most tests) keeps compiling
     * unchanged; the orchestrator itself always uses the full canonical constructor with the group's real
     * priority/order/plan/attempt number.
     */
    public ImplementationContext(
            String runId,
            String unitId,
            Path workspace,
            String branchName,
            String branchBaseSha,
            String verifiedSourceRef,
            AnalysisRemediationGroup group,
            List<ImplementationGroupMember> members,
            List<String> companionCoordinates) {
        this(runId, unitId, workspace, branchName, branchBaseSha, verifiedSourceRef, group, members,
                companionCoordinates, Severity.OTHER, 0, null, null, 1);
    }

    /**
     * Backward-compatible shape from before {@code repairContext}/{@code attemptNumber} existed --
     * defaults them to {@code null}/{@code 1}, the ordinary attempt-1 case. Kept so every existing caller
     * that never needed a repair attempt keeps compiling unchanged.
     */
    public ImplementationContext(
            String runId,
            String unitId,
            Path workspace,
            String branchName,
            String branchBaseSha,
            String verifiedSourceRef,
            AnalysisRemediationGroup group,
            List<ImplementationGroupMember> members,
            List<String> companionCoordinates,
            Severity priority,
            int executionOrder,
            PartialAnalysisState partialAnalysisState) {
        this(runId, unitId, workspace, branchName, branchBaseSha, verifiedSourceRef, group, members,
                companionCoordinates, priority, executionOrder, partialAnalysisState, null, 1);
    }

    /** Convenience for the ordinary case: one finding, no coordination with anything else. */
    public ImplementationContext(
            String runId,
            String unitId,
            Path workspace,
            String branchName,
            String branchBaseSha,
            String verifiedSourceRef,
            AnalysisRemediationGroup group,
            VulnerabilityWorkItem workItem,
            com.tungsten.depbot.assessment.FindingAssessment findingAssessment) {
        this(runId, unitId, workspace, branchName, branchBaseSha, verifiedSourceRef, group,
                List.of(new ImplementationGroupMember(workItem, findingAssessment)), List.of());
    }

    public boolean isSingleMember() {
        return members.size() == 1;
    }

    public List<String> memberCoordinates() {
        return members.stream().map(ImplementationGroupMember::coordinates).toList();
    }

    /** A summary of every coordinate this call covers, for logs, commit messages and progress lines. */
    public String coordinates() {
        List<String> all = memberCoordinates();
        return all.size() == 1 ? all.get(0) : String.join(", ", all);
    }
}
