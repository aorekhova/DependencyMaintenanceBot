package com.tungsten.depbot.remediation;

import java.util.List;
import java.util.Objects;

/**
 * The run-wide record of every validated remediation group's priority and execution order, fixed once
 * grouping and cohort partitioning are done and never changed mid-remediation (the analysis decides
 * membership once; Java fixes priority/order once; neither is revisited). Covers automatic and
 * non-automatic groups alike -- {@code executionOrder} is {@code null} for a group that never enters the
 * cumulative chain (routed straight to Human Review instead).
 */
public record GroupExecutionPlan(String runId, List<Entry> groups) {

    public GroupExecutionPlan {
        Objects.requireNonNull(runId, "runId");
        groups = groups == null ? List.of() : List.copyOf(groups);
    }

    public record Entry(
            String groupId,
            String priority,
            Integer executionOrder,
            List<String> memberCoordinates,
            String verdict,
            String cohortBranchName) {

        public Entry {
            Objects.requireNonNull(groupId, "groupId");
            Objects.requireNonNull(priority, "priority");
            Objects.requireNonNull(verdict, "verdict");
            memberCoordinates = memberCoordinates == null ? List.of() : List.copyOf(memberCoordinates);
        }
    }
}
