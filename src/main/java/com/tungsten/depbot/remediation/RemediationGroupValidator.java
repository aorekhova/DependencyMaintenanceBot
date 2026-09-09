package com.tungsten.depbot.remediation;

import com.tungsten.depbot.assessment.AnalysisRemediationGroup;
import com.tungsten.depbot.assessment.BatchAnalysis;
import com.tungsten.depbot.assessment.FindingAssessment;
import com.tungsten.depbot.assessment.VulnerabilityWorkItem;
import com.tungsten.depbot.implementation.ImplementationGroupMember;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Confirms that the remediation groups a {@link BatchAnalysis} proposes are trustworthy enough to route
 * onward -- without computing what those groups should have been.
 *
 * <p>This replaces the old {@code RemediationGroupBuilder}'s union-find entirely. Which findings belong
 * together is now Claude's own engineering judgement, reached during one investigation that saw every
 * finding in the batch at once; this class only checks the result against ground truth this application
 * itself controls. {@link BatchAnalysisParser} already confirmed a document is internally
 * self-consistent (every {@code REMEDIATION_REQUIRED} finding names a group that exists, every group is
 * claimed by at least one finding) -- what only this class can add is checking that against the
 * <em>original</em> batch of {@link VulnerabilityWorkItem}s, which the parser never sees: a
 * {@code memberCoordinates} entry that does not correspond to any real finding in this run is caught
 * here, not there.
 */
public final class RemediationGroupValidator {

    private RemediationGroupValidator() {
    }

    public static GroupingValidationOutcome validate(BatchAnalysis analysis, List<VulnerabilityWorkItem> workItems) {
        Objects.requireNonNull(analysis, "analysis");
        Objects.requireNonNull(workItems, "workItems");

        Map<String, VulnerabilityWorkItem> workItemsByCoordinates = new HashMap<>();
        for (VulnerabilityWorkItem workItem : workItems) {
            workItemsByCoordinates.put(workItem.coordinates(), workItem);
        }

        Map<String, FindingAssessment> findingsByCoordinates = new HashMap<>();
        for (FindingAssessment finding : analysis.findings()) {
            findingsByCoordinates.put(finding.coordinates(), finding);
        }

        List<ValidatedRemediationGroup> validGroups = new ArrayList<>();
        Map<String, String> invalidGroupReasons = new LinkedHashMap<>();

        for (AnalysisRemediationGroup group : analysis.remediationGroups()) {
            List<String> unknown = group.memberCoordinates().stream()
                    .filter(coordinates -> !workItemsByCoordinates.containsKey(coordinates))
                    .toList();

            if (!unknown.isEmpty()) {
                String reason = "Remediation group \"" + group.groupId() + "\" names member coordinate(s) "
                        + unknown + " that do not correspond to any finding in this batch, so this group "
                        + "cannot be trusted.";
                for (String coordinates : group.memberCoordinates()) {
                    invalidGroupReasons.put(coordinates, reason);
                }
                continue;
            }

            if (!group.implementationPlan().isEmpty() && group.plannedChanges().isEmpty()) {
                // A fresh analysis is held to a stricter metadata contract than partial-analysis salvage:
                // a narrative plan without the machine-readable plannedChanges needed for objective
                // verification is an incomplete analysis output, not a group Java can safely route.
                String reason = "Remediation group \"" + group.groupId() + "\" has a narrative "
                        + "implementationPlan but no machine-readable plannedChanges -- Vulnerability "
                        + "Analysis's own metadata contract for a fresh analysis is incomplete, so this "
                        + "group cannot be safely routed.";
                for (String coordinates : group.memberCoordinates()) {
                    invalidGroupReasons.put(coordinates, reason);
                }
                continue;
            }

            List<ImplementationGroupMember> members = group.memberCoordinates().stream()
                    .map(coordinates -> new ImplementationGroupMember(
                            workItemsByCoordinates.get(coordinates), findingsByCoordinates.get(coordinates)))
                    .toList();
            validGroups.add(new ValidatedRemediationGroup(group, members));
        }

        return new GroupingValidationOutcome(validGroups, invalidGroupReasons);
    }
}
