package com.tungsten.depbot.assessment;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Guards against exactly one failure mode: the second Vulnerability Analysis attempt answering a
 * finding it never actually looked at (whether because its session could not be resumed and it has no
 * memory of the first attempt, or because it simply ran out of its own reduced budget before reaching a
 * finding), rather than honestly reconstructing whatever either attempt had already established.
 *
 * <p>{@link BatchAnalysisSecondAttemptPromptRenderer} already tells Claude that any finding it did not
 * reach must come back {@code INCONCLUSIVE} with {@code risks} (or a summary) saying time or turns ran
 * out -- that is the documented, correct shape for "not reached." This validator flags exactly that
 * shape: an {@code INCONCLUSIVE} finding whose own summary or risks admit it was never examined, or one
 * with neither evidence nor risks at all. A genuinely investigated {@code INCONCLUSIVE} finding -- one
 * that honestly has no evidence bullets, only risks explaining what could not be established -- is never
 * flagged merely for lacking evidence: absence of evidence is not, by itself, evidence of absence of
 * investigation.
 *
 * <p><strong>Deliberately narrow.</strong> Only {@link AssessmentConclusion#INCONCLUSIVE} findings are
 * ever flagged -- a second attempt that genuinely established {@code REMEDIATION_REQUIRED} or
 * {@code NO_ACTION_REQUIRED} for a finding is trusted exactly as the first attempt would be, and this
 * class is never run against the first attempt's own output at all (see {@code BatchAnalysisService}):
 * Vulnerability Analysis stays a free investigation, not a checklist Java re-grades.
 */
public final class AnalysisCoverageValidator {

    private AnalysisCoverageValidator() {
    }

    /**
     * Phrases {@link BatchAnalysisFinalizationPromptRenderer} itself asks Claude to use for a finding it
     * never reached, plus the obvious synonyms a model might use instead. Matched case-insensitively as
     * a plain substring -- deliberately simple, since this only ever needs to catch an honest disclosure
     * of "I did not look at this," never to parse free text precisely.
     */
    private static final List<String> NOT_EXAMINED_PHRASES = List.of(
            "not examined", "not investigated", "not looked at", "no investigation",
            "budget exhausted", "ran out of time", "ran out of turns", "out of time",
            "out of turns", "time ran out", "turns ran out", "time budget", "turn budget");

    /**
     * @return empty when every finding in {@code analysis} carries real evidence that it was actually
     *         examined; otherwise a human-readable reason naming which findings do not
     */
    public static Optional<String> incompletenessReason(BatchAnalysis analysis) {
        List<String> unexamined = analysis.findings().stream()
                .filter(AnalysisCoverageValidator::showsNoRealCoverage)
                .map(FindingAssessment::coordinates)
                .toList();

        if (unexamined.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of("finalization answered " + unexamined.size() + " of " + analysis.findings().size()
                + " finding(s) as INCONCLUSIVE with no evidence of actually having been examined ("
                + String.join(", ", unexamined) + ") -- a placeholder answer for an unreached finding is "
                + "not a completed batch analysis for routing purposes");
    }

    private static boolean showsNoRealCoverage(FindingAssessment finding) {
        if (finding.conclusion() != AssessmentConclusion.INCONCLUSIVE) {
            return false;
        }
        // Not, by itself, "evidence is empty" -- a genuinely investigated finding can honestly end with
        // no evidence bullets at all, carrying only risks explaining what could not be established (see
        // Assessments.inconclusive() for exactly that shape). What actually distinguishes an unreached
        // placeholder is the language BatchAnalysisFinalizationPromptRenderer itself requires for one:
        // an explicit admission that time or turns ran out before this finding was looked at.
        if (finding.evidence().isEmpty() && finding.risks().isEmpty()) {
            return true;
        }
        return containsNotExaminedLanguage(finding.summary())
                || finding.risks().stream().anyMatch(AnalysisCoverageValidator::containsNotExaminedLanguage);
    }

    private static boolean containsNotExaminedLanguage(String text) {
        if (text == null || text.isBlank()) {
            return false;
        }
        String normalized = text.toLowerCase(Locale.ROOT);
        return NOT_EXAMINED_PHRASES.stream().anyMatch(normalized::contains);
    }
}
