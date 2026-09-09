package com.tungsten.depbot.assessment;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pure unit tests for the algorithm that decides whether a finalization-produced {@link BatchAnalysis}
 * actually covers the batch it claims to, or is a placeholder answer for findings that were never
 * examined. No Claude, no git, no I/O -- this runs in milliseconds.
 */
class AnalysisCoverageValidatorTest {

    private static FindingAssessment finding(
            AssessmentConclusion conclusion, String summary, List<String> evidence, List<String> risks) {
        return new FindingAssessment(
                "org.example:artifact", List.of("CVE-2026-1"), summary, conclusion, null, evidence, risks);
    }

    @Test
    void genuineConclusionsWithEvidencePassCoverage() {
        BatchAnalysis analysis = new BatchAnalysis("1.0", List.of(
                finding(AssessmentConclusion.NO_ACTION_REQUIRED, "not present on any ref",
                        List.of("dependency:tree is empty"), List.of()),
                finding(AssessmentConclusion.INCONCLUSIVE, "transitive reach could not be established",
                        List.of(), List.of("dependency:tree could not run offline"))),
                List.of());

        assertTrue(AnalysisCoverageValidator.incompletenessReason(analysis).isEmpty());
    }

    @Test
    void inconclusiveWithNoEvidenceAndNoRisksFailsCoverage() {
        BatchAnalysis analysis = new BatchAnalysis("1.0", List.of(
                finding(AssessmentConclusion.INCONCLUSIVE, "Not examined", List.of(), List.of())),
                List.of());

        Optional<String> reason = AnalysisCoverageValidator.incompletenessReason(analysis);
        assertTrue(reason.isPresent());
        assertTrue(reason.get().contains("org.example:artifact"), reason.get());
    }

    @Test
    void inconclusiveWithEvidenceButNotExaminedLanguageStillFailsCoverage() {
        BatchAnalysis analysis = new BatchAnalysis("1.0", List.of(
                finding(AssessmentConclusion.INCONCLUSIVE, "budget exhausted before this could be reached",
                        List.of("placeholder"), List.of())),
                List.of());

        assertTrue(AnalysisCoverageValidator.incompletenessReason(analysis).isPresent());
    }

    @Test
    void remediationRequiredAndNoActionRequiredAreNeverFlaggedRegardlessOfEvidence() {
        BatchAnalysis analysis = new BatchAnalysis("1.0", List.of(
                finding(AssessmentConclusion.NO_ACTION_REQUIRED, "not examined at all", List.of(), List.of())),
                List.of());

        assertFalse(AnalysisCoverageValidator.incompletenessReason(analysis).isPresent(),
                "coverage validation only ever looks at INCONCLUSIVE findings -- primary analysis stays a "
                        + "free investigation, not a checklist");
    }

    @Test
    void mixOfOneGenuineAndOnePlaceholderFindingFailsCoverage() {
        BatchAnalysis analysis = new BatchAnalysis("1.0", List.of(
                finding(AssessmentConclusion.NO_ACTION_REQUIRED, "confirmed absent",
                        List.of("dependency:tree is empty"), List.of()),
                finding(AssessmentConclusion.INCONCLUSIVE, "Not examined", List.of(), List.of("time ran out"))),
                List.of());

        Optional<String> reason = AnalysisCoverageValidator.incompletenessReason(analysis);
        assertTrue(reason.isPresent());
        assertTrue(reason.get().contains("1 of 2"), reason.get());
    }
}
