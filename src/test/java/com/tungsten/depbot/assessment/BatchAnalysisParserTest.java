package com.tungsten.depbot.assessment;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fast, no-Claude-needed regression tests for {@link BatchAnalysisParser} -- in particular, the
 * production defect from pilot {@code 20260908-162700-b5dce6}: a {@code plannedChanges} entry missing
 * its required {@code changeType} must fail closed with a precise diagnostic, never be silently defaulted
 * to a Java-invented value.
 */
class BatchAnalysisParserTest {

    private final BatchAnalysisParser parser = new BatchAnalysisParser();

    private static final String VALID_PLANNED_CHANGE = """
            {
              "dependencyCoordinates": "org.apache.httpcomponents.core5:httpcore5",
              "currentVersion": "5.2",
              "targetVersion": "5.3",
              "affectedFile": "pom.xml",
              "changeType": "DEPENDENCY_MANAGEMENT_ADDITION",
              "reason": "pin the new dependencyManagement entry to 5.3"
            }""";

    private static final String VALID_NO_ACTION_FINDING = """
            {
              "coordinates": "org.apache.httpcomponents.core5:httpcore5",
              "vulnerabilityIds": ["CVE-2026-1"],
              "summary": "not present on any ref this analysis examined",
              "conclusion": "NO_ACTION_REQUIRED",
              "evidence": ["dependency:tree is empty for every module"],
              "noActionBasis": "DEPENDENCY_NOT_PRESENT"
            }""";

    private static String documentWithFinding(String findingJson) {
        return """
                {
                  "schemaVersion": "1.0",
                  "findings": [
                    %s
                  ],
                  "remediationGroups": []
                }
                """.formatted(findingJson);
    }

    private static String documentWithPlannedChange(String plannedChangeJson) {
        return """
                {
                  "schemaVersion": "1.0",
                  "findings": [
                    {
                      "coordinates": "org.apache.httpcomponents.core5:httpcore5",
                      "vulnerabilityIds": ["CVE-2026-1"],
                      "summary": "needs a dependencyManagement pin",
                      "conclusion": "REMEDIATION_REQUIRED",
                      "remediationGroupId": "g-httpcomponents",
                      "evidence": ["evidence"]
                    }
                  ],
                  "remediationGroups": [
                    {
                      "groupId": "g-httpcomponents",
                      "memberCoordinates": ["org.apache.httpcomponents.core5:httpcore5"],
                      "groupingReason": "a single finding",
                      "sourceRef": "origin/release/9.2",
                      "sourceCommitSha": "0123456789abcdef0123456789abcdef01234567",
                      "origin": "DEPENDENCY_MANAGEMENT",
                      "dependencyRelationship": "declared directly",
                      "observedVersion": "5.2",
                      "recommendedRemediation": "pin the new BOM entry",
                      "recommendedTargetVersion": "5.3",
                      "affectedFiles": ["pom.xml"],
                      "impactScore": 2,
                      "impactReason": "one new pin",
                      "automationSafety": "AUTOMATIC_ALLOWED",
                      "automationSafetyReason": "no coordinated or runtime-sensitive dependency is involved",
                      "implementationPlan": ["add the dependencyManagement entry"],
                      "validationPlan": ["run dependency:tree"],
                      "plannedChanges": [
                        %s
                      ]
                    }
                  ]
                }
                """.formatted(plannedChangeJson);
    }

    @Test
    @DisplayName("a valid document with an explicit changeType on every plannedChanges entry parses normally")
    void validDocumentWithChangeTypeParsesNormally() {
        BatchAnalysis analysis = parser.parse(documentWithPlannedChange(VALID_PLANNED_CHANGE));

        assertEquals(1, analysis.remediationGroups().size());
        assertEquals(1, analysis.remediationGroups().get(0).plannedChanges().size());
        assertEquals(PlannedChangeType.DEPENDENCY_MANAGEMENT_ADDITION,
                analysis.remediationGroups().get(0).plannedChanges().get(0).changeType());
    }

    @Test
    @DisplayName("a plannedChanges entry missing changeType fails closed with a precise, located diagnostic "
            + "-- never silently defaulted to OTHER or any other value")
    void missingChangeTypeFailsClosedWithPreciseDiagnostic() {
        String malformed = VALID_PLANNED_CHANGE.replace(
                "\"changeType\": \"DEPENDENCY_MANAGEMENT_ADDITION\",\n", "");

        AssessmentParseException exception = assertThrows(AssessmentParseException.class,
                () -> parser.parse(documentWithPlannedChange(malformed)));

        assertEquals(AssessmentParseException.Kind.MALFORMED_ANALYSIS, exception.kind());
        assertTrue(exception.getMessage().contains("plannedChanges"), exception.getMessage());
        assertTrue(exception.getMessage().contains("changeType"), exception.getMessage());
        assertTrue(exception.getMessage().contains("is missing"), exception.getMessage());
    }

    @Test
    @DisplayName("an invalid changeType enum value fails closed through the same parse path")
    void invalidChangeTypeEnumFailsClosed() {
        String malformed = VALID_PLANNED_CHANGE.replace(
                "\"DEPENDENCY_MANAGEMENT_ADDITION\"", "\"NOT_A_REAL_TYPE\"");

        AssessmentParseException exception = assertThrows(AssessmentParseException.class,
                () -> parser.parse(documentWithPlannedChange(malformed)));

        assertEquals(AssessmentParseException.Kind.MALFORMED_ANALYSIS, exception.kind());
        assertTrue(exception.getMessage().contains("NOT_A_REAL_TYPE"), exception.getMessage());
    }

    @Test
    @DisplayName("a missing changeType never parses successfully -- there is no code path that defaults it")
    void missingChangeTypeNeverSilentlyParses() {
        String malformed = VALID_PLANNED_CHANGE.replace(
                "\"changeType\": \"DEPENDENCY_MANAGEMENT_ADDITION\",\n", "");
        String document = documentWithPlannedChange(malformed);

        // The only two possible outcomes are "throws" (asserted above) or "returns a record whose
        // changeType is a real, Claude-supplied value" -- there is no third outcome where parsing
        // succeeds with a Java-invented changeType. This test exists to make that invariant explicit,
        // not merely incidental to the exception test above.
        assertThrows(AssessmentParseException.class, () -> parser.parse(document));
    }

    // ---- NO_ACTION_REQUIRED must carry a noActionBasis -- production defect from pilot
    // 20260908-162700-b5dce6: a jsoup finding concluded NO_ACTION_REQUIRED by reading Mend's own
    // "through 1.23.2, fixed in commit 862ba2f" phrasing literally, without resolving it against a more
    // authoritative source, even though 1.23.2 already contained the fix. These tests exercise the
    // general contract that catches that shape of error -- nothing here names jsoup or any CVE in
    // production code; the fixture below is only a scenario, not a special case the parser recognises.

    @Test
    @DisplayName("a NO_ACTION_REQUIRED finding with an explicit noActionBasis parses normally")
    void noActionRequiredWithBasisParsesNormally() {
        BatchAnalysis analysis = parser.parse(documentWithFinding(VALID_NO_ACTION_FINDING));

        assertEquals(NoActionBasis.DEPENDENCY_NOT_PRESENT, analysis.findings().get(0).noActionBasis());
    }

    @Test
    @DisplayName("a NO_ACTION_REQUIRED finding missing noActionBasis fails closed -- a well-evidenced "
            + "absence still has to say which of the recognised grounds it actually rests on")
    void noActionRequiredWithoutBasisFailsClosed() {
        String malformed = VALID_NO_ACTION_FINDING.replace(
                "\"noActionBasis\": \"DEPENDENCY_NOT_PRESENT\"\n", "\"noActionBasis\": null\n");

        AssessmentParseException exception = assertThrows(AssessmentParseException.class,
                () -> parser.parse(documentWithFinding(malformed)));

        assertEquals(AssessmentParseException.Kind.ANALYSIS_VALIDATION_FAILED, exception.kind());
        assertTrue(exception.getMessage().contains("noActionBasis"), exception.getMessage());
    }

    @Test
    @DisplayName("an invalid noActionBasis enum value fails closed through the same parse path")
    void invalidNoActionBasisEnumFailsClosed() {
        String malformed = VALID_NO_ACTION_FINDING.replace(
                "\"DEPENDENCY_NOT_PRESENT\"", "\"PROBABLY_FINE\"");

        AssessmentParseException exception = assertThrows(AssessmentParseException.class,
                () -> parser.parse(documentWithFinding(malformed)));

        assertEquals(AssessmentParseException.Kind.MALFORMED_ANALYSIS, exception.kind());
        assertTrue(exception.getMessage().contains("PROBABLY_FINE"), exception.getMessage());
    }

    @Test
    @DisplayName("noActionBasis set on a REMEDIATION_REQUIRED finding fails closed -- it only applies to "
            + "NO_ACTION_REQUIRED")
    void noActionBasisSetOnRemediationRequiredFailsClosed() {
        String finding = """
                {
                  "coordinates": "org.apache.httpcomponents.core5:httpcore5",
                  "vulnerabilityIds": ["CVE-2026-1"],
                  "summary": "needs a version bump",
                  "conclusion": "REMEDIATION_REQUIRED",
                  "remediationGroupId": "g-httpcomponents",
                  "evidence": ["evidence"],
                  "noActionBasis": "DEPENDENCY_NOT_PRESENT"
                }""";

        AssessmentParseException exception = assertThrows(AssessmentParseException.class,
                () -> parser.parse(documentWithFinding(finding)));

        assertEquals(AssessmentParseException.Kind.ANALYSIS_VALIDATION_FAILED, exception.kind());
        assertTrue(exception.getMessage().contains("noActionBasis"), exception.getMessage());
    }

    @Test
    @DisplayName("production regression: a jsoup-shaped NO_ACTION_REQUIRED finding that omits noActionBasis "
            + "fails closed exactly like any other missing-noActionBasis finding -- proving the general "
            + "contract catches this specific pilot's failure shape without any jsoup- or CVE-specific "
            + "logic in production code")
    void jsoupStyleContradictoryNoActionRequiredWithoutBasisFailsClosed() {
        String jsoupFinding = """
                {
                  "coordinates": "org.jsoup:jsoup",
                  "vulnerabilityIds": ["CVE-2026-30203"],
                  "summary": "Mend reports this as vulnerable through 1.23.2, fixed in commit 862ba2f",
                  "conclusion": "NO_ACTION_REQUIRED",
                  "evidence": ["Mend's own text reads \\"through 1.23.2, fixed in commit 862ba2f\\""]
                }""";

        AssessmentParseException exception = assertThrows(AssessmentParseException.class,
                () -> parser.parse(documentWithFinding(jsoupFinding)));

        assertEquals(AssessmentParseException.Kind.ANALYSIS_VALIDATION_FAILED, exception.kind());
        assertTrue(exception.getMessage().contains("noActionBasis"), exception.getMessage());
    }
}
