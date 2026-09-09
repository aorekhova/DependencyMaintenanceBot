package com.tungsten.depbot.remediation;

import com.tungsten.depbot.implementation.ImplementationGroupMember;
import com.tungsten.depbot.report.Severity;

import java.util.Comparator;
import java.util.List;

/**
 * Computes a remediation group's execution priority deterministically from its members' own
 * severities -- never an extra Claude call. The most severe member's severity wins: a group with one
 * CRITICAL and one HIGH member is a CRITICAL-priority group.
 *
 * <p>Ranked through {@link Severity#executionPriorityRank()}, never {@link Severity#ordinal()} -- see
 * that method's own javadoc for why the two must not be conflated for this purpose.
 */
public final class GroupPriority {

    private GroupPriority() {
    }

    public static Severity of(List<ImplementationGroupMember> members) {
        return members.stream()
                .map(member -> Severity.fromRaw(member.workItem().maxSeverity()))
                .min(Comparator.comparingInt(Severity::executionPriorityRank))
                .orElse(Severity.OTHER);
    }
}
