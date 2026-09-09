package com.tungsten.depbot.assessment;

import java.util.List;

/**
 * One Mend finding's own conclusion, as part of a whole-batch {@link BatchAnalysis}.
 *
 * <p>Deliberately lightweight: everything about <em>how</em> a {@code REMEDIATION_REQUIRED} finding
 * should be fixed -- the plan, the automation-safety judgement, the size, the ref to branch from --
 * belongs to the {@link AnalysisRemediationGroup} it points at through {@code remediationGroupId}, not
 * to the finding itself. A finding is one member of at most one group; the group, not the finding, is
 * what gets implemented, verified and committed.
 */
public record FindingAssessment(
        String coordinates,
        List<String> vulnerabilityIds,
        String summary,
        AssessmentConclusion conclusion,
        String remediationGroupId,
        List<String> evidence,
        List<String> risks,
        NoActionBasis noActionBasis) {

    public FindingAssessment {
        vulnerabilityIds = immutable(vulnerabilityIds);
        evidence = immutable(evidence);
        risks = immutable(risks);
    }

    /** Backward-compatible: no {@code noActionBasis}, for callers built before that field existed. */
    public FindingAssessment(
            String coordinates, List<String> vulnerabilityIds, String summary, AssessmentConclusion conclusion,
            String remediationGroupId, List<String> evidence, List<String> risks) {
        this(coordinates, vulnerabilityIds, summary, conclusion, remediationGroupId, evidence, risks, null);
    }

    /** Whether this finding claims to belong to a remediation group. */
    public boolean hasRemediationGroup() {
        return remediationGroupId != null && !remediationGroupId.isBlank();
    }

    private static List<String> immutable(List<String> values) {
        return values == null ? List.of() : List.copyOf(values);
    }
}
