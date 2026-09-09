package com.tungsten.depbot.implementation;

import com.tungsten.depbot.assessment.FindingAssessment;
import com.tungsten.depbot.assessment.VulnerabilityWorkItem;

import java.util.Objects;

/**
 * One finding and its own conclusion, as carried into a (possibly multi-member)
 * {@link ImplementationContext}.
 *
 * <p>The group's shared plan, source ref and automation decision live on {@link ImplementationContext}
 * itself now, not here -- {@link FindingAssessment} only carries what is genuinely per-finding: its own
 * conclusion, summary, evidence and risks.
 */
public record ImplementationGroupMember(VulnerabilityWorkItem workItem, FindingAssessment findingAssessment) {

    public ImplementationGroupMember {
        Objects.requireNonNull(workItem, "workItem");
        Objects.requireNonNull(findingAssessment, "findingAssessment");
    }

    public String coordinates() {
        return workItem.coordinates();
    }
}
