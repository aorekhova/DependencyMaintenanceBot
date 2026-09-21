package com.tungsten.depbot.implementation;

import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;
import com.tungsten.depbot.remediation.RejectionStage;
import com.tungsten.depbot.validation.ValidationOutcome;

import java.util.List;
import java.util.Objects;

/**
 * Everything the repair attempt needs to fix a specific, already-diagnosed problem -- never to
 * investigate the group from scratch: the diff the immediately preceding attempt actually produced,
 * exactly which stage rejected it, and whatever evidence that stage produced.
 *
 * <p>Only the field or fields matching {@code failedStage} are ever populated; the rest are {@code null}
 * -- a repair prompt built from this should never have to guess which piece of evidence is the real one.
 *
 * <p>{@code priorAttemptsEvidence} is {@code List.of()} for attempt 2 of every group (there is no attempt
 * before the one this context already fully describes). For an {@code EXTENDED} group's attempt 3 (see
 * {@link com.tungsten.depbot.assessment.ImplementationBudget}), it carries forward what attempt 1 and
 * attempt 2 already established, one entry per earlier attempt, in order -- fixing run
 * {@code 20260920-031107-148632}'s attempt-3 evidence loss: rebuilding a repair context from only the
 * immediately preceding attempt discarded attempt 1's own dependency-validation finding entirely once
 * attempt 2 was rejected for an unrelated (e.g. plan-conformance) reason, so attempt 3 saw only "unauthorized
 * file changed" with no explanation of why that file had been touched in the first place. Each entry is a
 * short, self-contained summary (the attempt's own failure evidence, plus its own report's
 * {@code divergenceFromAssessment} when it explains a discovered file/path) -- never the full evidence
 * objects again, which would just repeat what {@link ImplementationPromptRenderer} already rendered for
 * that attempt's own turn.
 */
public record RepairContext(
        String implementationDiff,
        RejectionStage failedStage,
        ValidationOutcome dependencyValidationOutcome,
        ValidationOutcome fullBuildValidationOutcome,
        JenkinsValidationOutcome cumulativeJenkinsValidation,
        String jenkinsConsoleLogExcerpt,
        List<String> conformanceViolations,
        String exactErrorEvidenceSummary,
        List<String> priorAttemptsEvidence) {

    public RepairContext {
        Objects.requireNonNull(failedStage, "failedStage");
        Objects.requireNonNull(exactErrorEvidenceSummary, "exactErrorEvidenceSummary");
        conformanceViolations = conformanceViolations == null ? List.of() : List.copyOf(conformanceViolations);
        priorAttemptsEvidence = priorAttemptsEvidence == null ? List.of() : List.copyOf(priorAttemptsEvidence);
    }

    /**
     * Backward-compatible shape from before {@code priorAttemptsEvidence} existed -- defaults it to
     * {@code List.of()}. Kept so every existing caller/test keeps compiling unchanged.
     */
    public RepairContext(
            String implementationDiff,
            RejectionStage failedStage,
            ValidationOutcome dependencyValidationOutcome,
            ValidationOutcome fullBuildValidationOutcome,
            JenkinsValidationOutcome cumulativeJenkinsValidation,
            String jenkinsConsoleLogExcerpt,
            List<String> conformanceViolations,
            String exactErrorEvidenceSummary) {
        this(implementationDiff, failedStage, dependencyValidationOutcome, fullBuildValidationOutcome,
                cumulativeJenkinsValidation, jenkinsConsoleLogExcerpt, conformanceViolations,
                exactErrorEvidenceSummary, List.of());
    }
}
