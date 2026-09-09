package com.tungsten.depbot.remediation;

import com.tungsten.depbot.assessment.AnalysisRemediationGroup;
import com.tungsten.depbot.implementation.ImplementationGroupMember;

import java.util.List;
import java.util.Objects;

/**
 * One {@link AnalysisRemediationGroup} after {@link RemediationGroupValidator} confirmed every one of
 * its member coordinates is a real finding from this batch -- resolved to the actual
 * {@link ImplementationGroupMember}s (finding plus its own conclusion) it names.
 *
 * <p>Not yet a {@link RemediationGroup}: the source ref still has to be independently verified through
 * git, which is the orchestrator's job, not the validator's -- structural validation and git
 * verification are deliberately kept as separate steps.
 */
public record ValidatedRemediationGroup(
        AnalysisRemediationGroup source, List<ImplementationGroupMember> members) {

    public ValidatedRemediationGroup {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(members, "members");
        if (members.isEmpty()) {
            throw new IllegalArgumentException("a validated remediation group must have at least one member");
        }
        members = List.copyOf(members);
    }
}
