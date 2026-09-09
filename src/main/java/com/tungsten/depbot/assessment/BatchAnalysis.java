package com.tungsten.depbot.assessment;

import java.util.List;

/**
 * The whole answer from one Vulnerability Analysis Engineer call: every finding in the batch, and the
 * remediation groups Claude itself decided are needed.
 *
 * <p>Java never computes grouping from this document -- {@code findings} and {@code remediationGroups}
 * are only cross-checked for structural consistency (every {@code REMEDIATION_REQUIRED} finding names
 * a group that actually exists and lists it back as a member, and vice versa) by
 * {@link com.tungsten.depbot.remediation.RemediationGroupValidator}. Which findings belong together,
 * and why, is Claude's own engineering judgement, reached freely during one investigation that saw
 * every finding in the run at once.
 */
public record BatchAnalysis(
        String schemaVersion,
        List<FindingAssessment> findings,
        List<AnalysisRemediationGroup> remediationGroups) {

    /** The schema generation this application understands. */
    public static final String CURRENT_SCHEMA_VERSION = "1.0";

    public BatchAnalysis {
        schemaVersion = (schemaVersion == null || schemaVersion.isBlank())
                ? CURRENT_SCHEMA_VERSION
                : schemaVersion.strip();
        findings = immutableFindings(findings);
        remediationGroups = immutableGroups(remediationGroups);
    }

    private static List<FindingAssessment> immutableFindings(List<FindingAssessment> values) {
        return values == null ? List.of() : List.copyOf(values);
    }

    private static List<AnalysisRemediationGroup> immutableGroups(List<AnalysisRemediationGroup> values) {
        return values == null ? List.of() : List.copyOf(values);
    }
}
