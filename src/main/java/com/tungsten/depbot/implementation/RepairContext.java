package com.tungsten.depbot.implementation;

import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;
import com.tungsten.depbot.remediation.RejectionStage;
import com.tungsten.depbot.validation.ValidationOutcome;

import java.util.List;
import java.util.Objects;

/**
 * Everything the repair attempt needs to fix a specific, already-diagnosed problem -- never to
 * investigate the group from scratch: the diff attempt 1 actually produced, exactly which stage
 * rejected it, and whatever evidence that stage produced.
 *
 * <p>Only the field or fields matching {@code failedStage} are ever populated; the rest are {@code null}
 * -- a repair prompt built from this should never have to guess which piece of evidence is the real one.
 */
public record RepairContext(
        String implementationDiff,
        RejectionStage failedStage,
        ValidationOutcome dependencyValidationOutcome,
        ValidationOutcome fullBuildValidationOutcome,
        JenkinsValidationOutcome cumulativeJenkinsValidation,
        String jenkinsConsoleLogExcerpt,
        List<String> conformanceViolations,
        String exactErrorEvidenceSummary) {

    public RepairContext {
        Objects.requireNonNull(failedStage, "failedStage");
        Objects.requireNonNull(exactErrorEvidenceSummary, "exactErrorEvidenceSummary");
        conformanceViolations = conformanceViolations == null ? List.of() : List.copyOf(conformanceViolations);
    }
}
