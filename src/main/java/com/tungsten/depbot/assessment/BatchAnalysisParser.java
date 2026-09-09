package com.tungsten.depbot.assessment;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.claude.JsonAnswerExtractor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Turns the Vulnerability Analysis Engineer's final message into a validated {@link BatchAnalysis}.
 *
 * <p>Same extraction approach as the old single-finding parser: the answer is a developer's write-up,
 * prose and all, and the document to bind is the <em>last</em> complete JSON object in it.
 *
 * <p>Validation covers two things, deliberately kept separate from what
 * {@link com.tungsten.depbot.remediation.RemediationGroupValidator} does afterwards: this class checks
 * that the document itself is internally well-formed (every field a conclusion requires is present);
 * the validator checks that the resulting groups are safe to route into a shared branch. Both are
 * "validate the structure Claude returned," never "compute what the structure should have been."
 */
public final class BatchAnalysisParser {

    private final JsonMapper mapper = JsonMapper.builder()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    /**
     * @param answerText Claude's final message, prose and all
     * @throws AssessmentParseException if no batch analysis document could be found, it could not be
     *                                  bound, or it does not satisfy what its own findings/groups require
     */
    public BatchAnalysis parse(String answerText) {
        if (answerText == null || answerText.isBlank()) {
            throw new AssessmentParseException(
                    "The analysis produced no answer text to read.", AssessmentParseException.Kind.MISSING_ANALYSIS);
        }

        String json = JsonAnswerExtractor.lastJsonObject(answerText);
        if (json == null) {
            throw new AssessmentParseException(
                    "The analysis answer contains no complete JSON object, so there is no batch analysis "
                            + "document to read.",
                    AssessmentParseException.Kind.MISSING_ANALYSIS);
        }

        BatchAnalysis analysis;
        try {
            analysis = mapper.readValue(json, BatchAnalysis.class);
        } catch (JsonProcessingException e) {
            throw new AssessmentParseException(
                    "The batch analysis document could not be read: " + diagnosticMessage(e),
                    AssessmentParseException.Kind.MALFORMED_ANALYSIS, e);
        }

        validate(analysis);
        return analysis;
    }

    private static void validate(BatchAnalysis analysis) {
        List<String> problems = new ArrayList<>();

        if (!BatchAnalysis.CURRENT_SCHEMA_VERSION.equals(analysis.schemaVersion())) {
            problems.add("schemaVersion is \"" + analysis.schemaVersion() + "\", but this application "
                    + "understands only \"" + BatchAnalysis.CURRENT_SCHEMA_VERSION + "\"");
        }
        if (analysis.findings().isEmpty()) {
            problems.add("findings is empty, so the analysis reached no conclusion about anything it "
                    + "was asked to investigate");
        }

        Set<String> groupIds = new HashSet<>();
        for (AnalysisRemediationGroup group : analysis.remediationGroups()) {
            if (isBlank(group.groupId())) {
                problems.add("a remediation group has no groupId, so findings cannot reference it");
                continue;
            }
            if (!groupIds.add(group.groupId())) {
                problems.add("groupId \"" + group.groupId() + "\" is used by more than one remediation group");
            }
            validateGroup(group, problems);
        }

        for (FindingAssessment finding : analysis.findings()) {
            validateFinding(finding, groupIds, problems);
        }

        // Every memberCoordinates entry a group lists must have a matching finding that actually points
        // back at that exact group -- not merely "some finding somewhere claims some group" -- so that
        // RemediationGroupValidator can later resolve every member to a real FindingAssessment with no
        // gap. Checked in both directions: a group naming a member nothing claims, and (already covered
        // above, per-finding) a finding naming a group that does not exist.
        Map<String, String> declaredGroupByCoordinates = new HashMap<>();
        for (FindingAssessment finding : analysis.findings()) {
            if (finding.hasRemediationGroup()) {
                declaredGroupByCoordinates.put(finding.coordinates(), finding.remediationGroupId());
            }
        }
        Set<String> claimedGroupIds = new HashSet<>(declaredGroupByCoordinates.values());
        for (AnalysisRemediationGroup group : analysis.remediationGroups()) {
            if (group.groupId() == null) {
                continue;
            }
            if (!claimedGroupIds.contains(group.groupId())) {
                problems.add("remediation group \"" + group.groupId() + "\" is not claimed by any finding's "
                        + "remediationGroupId");
                continue;
            }
            for (String member : group.memberCoordinates()) {
                String declaredGroup = declaredGroupByCoordinates.get(member);
                if (declaredGroup == null) {
                    problems.add("remediation group \"" + group.groupId() + "\" lists member \"" + member
                            + "\", but no finding with that coordinates names this group in remediationGroupId");
                } else if (!declaredGroup.equals(group.groupId())) {
                    problems.add("remediation group \"" + group.groupId() + "\" lists member \"" + member
                            + "\", but that finding's remediationGroupId is \"" + declaredGroup + "\" instead");
                }
            }
        }

        if (!problems.isEmpty()) {
            throw new AssessmentParseException(
                    "The batch analysis document is not valid: " + String.join("; ", problems) + ".",
                    AssessmentParseException.Kind.ANALYSIS_VALIDATION_FAILED);
        }
    }

    private static void validateFinding(FindingAssessment finding, Set<String> groupIds, List<String> problems) {
        String coordinates = isBlank(finding.coordinates()) ? "(missing coordinates)" : finding.coordinates();

        if (isBlank(finding.coordinates())) {
            problems.add("a finding has no coordinates, so it is not clear which library it is about");
        }
        if (isBlank(finding.summary())) {
            problems.add(coordinates + ": summary is missing, so the finding does not state what it concluded");
        }
        if (finding.conclusion() == null) {
            problems.add(coordinates + ": conclusion is missing");
            return;
        }

        switch (finding.conclusion()) {
            case REMEDIATION_REQUIRED -> {
                if (!finding.hasRemediationGroup()) {
                    problems.add(coordinates + ": conclusion is REMEDIATION_REQUIRED but remediationGroupId "
                            + "is missing, so there is no group carrying its plan");
                } else if (!groupIds.contains(finding.remediationGroupId())) {
                    problems.add(coordinates + ": remediationGroupId \"" + finding.remediationGroupId()
                            + "\" does not name any remediation group in this analysis");
                }
                if (finding.noActionBasis() != null) {
                    problems.add(coordinates + ": conclusion is REMEDIATION_REQUIRED but noActionBasis is "
                            + "set -- that only applies to a NO_ACTION_REQUIRED conclusion");
                }
            }
            case NO_ACTION_REQUIRED -> {
                if (finding.evidence().isEmpty()) {
                    problems.add(coordinates + ": a NO_ACTION_REQUIRED conclusion carries no evidence, so "
                            + "there is nothing showing the dependency was actually looked for");
                }
                if (finding.hasRemediationGroup()) {
                    problems.add(coordinates + ": conclusion is NO_ACTION_REQUIRED but remediationGroupId "
                            + "is set -- there is nothing here to remediate together with anything");
                }
                if (finding.noActionBasis() == null) {
                    problems.add(coordinates + ": a NO_ACTION_REQUIRED conclusion carries no noActionBasis, "
                            + "so it is not stated whether the dependency is absent, no fixed version exists, "
                            + "or the version in effect here already meets or exceeds one -- a well-evidenced "
                            + "absence still has to say which of these it actually is");
                }
            }
            case INCONCLUSIVE -> {
                if (finding.risks().isEmpty() && finding.evidence().isEmpty()) {
                    problems.add(coordinates + ": an INCONCLUSIVE conclusion carries neither risks nor "
                            + "evidence, so it does not say what could not be established");
                }
                if (finding.hasRemediationGroup()) {
                    problems.add(coordinates + ": conclusion is INCONCLUSIVE but remediationGroupId is set "
                            + "-- an inconclusive finding cannot anchor a remediation group");
                }
                if (finding.noActionBasis() != null) {
                    problems.add(coordinates + ": conclusion is INCONCLUSIVE but noActionBasis is set -- "
                            + "that only applies to a NO_ACTION_REQUIRED conclusion");
                }
            }
        }
    }

    /**
     * What a remediation group must carry to be actionable -- the same fields the old per-finding
     * {@code REMEDIATION_REQUIRED} validation required, now checked at group level.
     */
    private static void validateGroup(AnalysisRemediationGroup group, List<String> problems) {
        String label = isBlank(group.groupId()) ? "(unnamed group)" : "group \"" + group.groupId() + "\"";

        if (group.memberCoordinates().isEmpty()) {
            problems.add(label + ": memberCoordinates is empty, so nothing is actually in this group");
        }
        if (!group.hasImpactScore()) {
            problems.add(label + ": impactScore is missing, so the size of the proposed change is unknown");
        }
        if (isBlank(group.impactReason())) {
            problems.add(label + ": impactReason is missing, so the score is unexplained");
        }
        if (!group.hasAutomationSafety()) {
            problems.add(label + ": automationSafety is missing, so it is unknown whether this may be "
                    + "trusted to automation");
        }
        if (isBlank(group.automationSafetyReason())) {
            problems.add(label + ": automationSafetyReason is missing, so the automation-safety decision "
                    + "is unexplained");
        }
        if (isBlank(group.recommendedRemediation())) {
            problems.add(label + ": recommendedRemediation is missing, so it is not stated what should be done");
        }
        if (group.implementationPlan().isEmpty()) {
            problems.add(label + ": implementationPlan is empty, so there is nothing for the implementation "
                    + "to carry out");
        }
        if (group.validationPlan().isEmpty()) {
            problems.add(label + ": validationPlan is empty, so there is no stated way to check the result");
        }
    }

    /**
     * The innermost cause's message, prefixed with Jackson's own field/index path when it tracked one
     * (e.g. {@code remediationGroups[0].plannedChanges[0]}) -- so a missing-field {@link
     * NullPointerException} whose own message is just the field's bare name (a record's compact
     * constructor argument name, from {@code Objects.requireNonNull(fieldName, ...)}) reads as
     * {@code "remediationGroups[0].plannedChanges[0].changeType is missing"} instead of the bare word
     * {@code "changeType"} alone. Never includes the surrounding answer text itself -- see this class's
     * own javadoc on why raw repository-derived text is never quoted in a diagnostic.
     */
    private static String diagnosticMessage(JsonProcessingException exception) {
        String path = jsonPath(exception);
        Throwable cause = exception;
        while (cause.getCause() != null && cause.getCause() != cause) {
            cause = cause.getCause();
        }
        String message = cause.getMessage();
        String detail = (message == null || message.isBlank()) ? cause.getClass().getSimpleName() : message;

        if (path == null) {
            return detail;
        }
        // A bare identifier-shaped message is exactly what Objects.requireNonNull(fieldName, ...) leaves
        // behind for a missing required field -- pair it with the path Jackson already tracked rather
        // than print the field name alone with no location.
        if (cause instanceof NullPointerException && detail.matches("[A-Za-z][A-Za-z0-9]*")) {
            return path + "." + detail + " is missing";
        }
        return path + ": " + detail;
    }

    /** Jackson's own field/index path for where a binding failure occurred, e.g.
     *  {@code remediationGroups[0].plannedChanges[0]} -- {@code null} when Jackson tracked no path
     *  (a top-level binding failure has nowhere further to point). */
    private static String jsonPath(JsonProcessingException exception) {
        if (!(exception instanceof JsonMappingException mappingException) || mappingException.getPath().isEmpty()) {
            return null;
        }
        StringBuilder path = new StringBuilder();
        for (JsonMappingException.Reference reference : mappingException.getPath()) {
            if (reference.getFieldName() != null) {
                if (path.length() > 0) {
                    path.append('.');
                }
                path.append(reference.getFieldName());
            } else if (reference.getIndex() >= 0) {
                path.append('[').append(reference.getIndex()).append(']');
            }
        }
        return path.length() > 0 ? path.toString() : null;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
