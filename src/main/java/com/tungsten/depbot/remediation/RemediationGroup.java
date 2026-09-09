package com.tungsten.depbot.remediation;

import com.tungsten.depbot.assessment.AnalysisRemediationGroup;
import com.tungsten.depbot.assessment.PartialAnalysisState;
import com.tungsten.depbot.implementation.ImplementationGroupMember;
import com.tungsten.depbot.report.Severity;

import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * One remediation group as the Vulnerability Analysis Engineer determined it, with its source ref
 * independently verified through git -- implemented, validated, committed and built together, as one
 * commit on whichever shared branch its {@link RemediationCohort} lands on.
 *
 * <p>Unlike the old {@code RemediationGroupBuilder}, nothing here computes membership: {@code source} is
 * exactly the {@link AnalysisRemediationGroup} Claude returned, already checked by
 * {@link RemediationGroupValidator} for internal consistency with the batch's findings.
 * {@code verifiedSourceSha} is the one thing the bot itself establishes -- {@code source.sourceRef()}
 * resolved through git, never the SHA Claude claimed -- which is what lets groups from different verified
 * refs be told apart and routed to separate {@link RemediationCohort}s rather than sharing a branch that
 * cannot actually be both refs at once.
 *
 * <p>{@code companionCoordinates} are coordinates named by the analysis as related that carry no Mend
 * finding of their own -- nothing for the bot to have assessed independently, but still part of the
 * context the implementation is given.
 *
 * <p>{@code partialAnalysisState} is {@code null} for every ordinary group -- it exists only so the one
 * shared {@code VulnerabilityRemediationService#runCohort} implementation call site can forward it onto
 * {@code ImplementationContext} without needing a second code path: a partial-analysis fallback group
 * (see {@code VulnerabilityRemediationService}) carries the two analysis attempts' combined progress
 * here, a synthetic single-member group built when Vulnerability Analysis could not complete but real
 * progress from it must still reach the Remediation Engineer.
 */
public record RemediationGroup(
        String groupId,
        String verifiedSourceRef,
        String verifiedSourceSha,
        AnalysisRemediationGroup source,
        List<ImplementationGroupMember> members,
        List<String> companionCoordinates,
        List<String> groupingNotes,
        int executionOrder,
        PartialAnalysisState partialAnalysisState) {

    public RemediationGroup {
        Objects.requireNonNull(groupId, "groupId");
        Objects.requireNonNull(verifiedSourceRef, "verifiedSourceRef");
        Objects.requireNonNull(verifiedSourceSha, "verifiedSourceSha");
        Objects.requireNonNull(source, "source");
        if (members == null || members.isEmpty()) {
            throw new IllegalArgumentException("a remediation group must have at least one member");
        }
        members = List.copyOf(members);
        companionCoordinates = companionCoordinates == null ? List.of() : List.copyOf(companionCoordinates);
        groupingNotes = groupingNotes == null ? List.of() : List.copyOf(groupingNotes);
    }

    /**
     * Backward-compatible shape from before the partial-analysis fallback existed -- defaults
     * {@code partialAnalysisState} to {@code null} (the ordinary case). Kept so every existing caller
     * keeps compiling unchanged.
     */
    public RemediationGroup(
            String groupId,
            String verifiedSourceRef,
            String verifiedSourceSha,
            AnalysisRemediationGroup source,
            List<ImplementationGroupMember> members,
            List<String> companionCoordinates,
            List<String> groupingNotes,
            int executionOrder) {
        this(groupId, verifiedSourceRef, verifiedSourceSha, source, members, companionCoordinates,
                groupingNotes, executionOrder, null);
    }

    /** The group's execution priority, deterministically from its members' severities -- see {@link GroupPriority}. */
    public Severity priority() {
        return GroupPriority.of(members);
    }

    /** A copy with {@code executionOrder} set -- assigned once cohort partitioning/ordering is known. */
    public RemediationGroup withExecutionOrder(int executionOrder) {
        return new RemediationGroup(groupId, verifiedSourceRef, verifiedSourceSha, source, members,
                companionCoordinates, groupingNotes, executionOrder, partialAnalysisState);
    }

    public List<String> memberCoordinates() {
        return members.stream().map(ImplementationGroupMember::coordinates).toList();
    }

    public boolean isSingleton() {
        return members.size() == 1;
    }

    /** A summary of every coordinate this group covers, for logs, commit messages and progress lines. */
    public String coordinatesSummary() {
        List<String> all = memberCoordinates();
        return all.size() == 1 ? all.get(0) : String.join(", ", all);
    }

    /** The most severe severity across every member -- what the branch name is labelled with. */
    public String maxSeverity() {
        return members.stream()
                .map(member -> member.workItem().maxSeverity())
                .min(Comparator.comparingInt(raw -> Severity.fromRaw(raw).ordinal()))
                .orElseThrow();
    }
}
