package com.tungsten.depbot.implementation;

import com.tungsten.depbot.claude.ClaudeRunOutcome;
import com.tungsten.depbot.git.ChangeDisposition;
import com.tungsten.depbot.git.ChangeOutcome;
import com.tungsten.depbot.validation.ValidationOutcome;
import com.tungsten.depbot.validation.ValidationStatus;

import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;

/**
 * What one implementation call produced: the report when there is a valid one, and what the orchestrator
 * did with the working tree either way.
 *
 * <p>{@code report} is {@code null} whenever there is nothing valid to hold -- the call failed, timed out,
 * or answered with something that would not validate -- and in every one of those cases
 * {@code change.disposition()} is {@link ChangeDisposition#ROLLED_BACK} or
 * {@link ChangeDisposition#NO_CHANGES}. Nothing is ever committed on the strength of an answer this
 * application could not read.
 *
 * <p>{@code fullBuildValidation} is {@code null} whenever {@code change.committed()} is {@code false} --
 * a full build only has something to check once a commit actually exists. When it does exist, the full
 * build always runs; a failing build never changes {@code change}, since by the time it runs the commit
 * has already been made and this stage is purely diagnostic.
 */
public record ImplementationOutcome(
        String runId,
        String unitId,
        String coordinates,
        String branchName,
        ImplementationReport report,
        ChangeOutcome change,
        ValidationOutcome validation,
        ValidationOutcome fullBuildValidation,
        ClaudeRunOutcome claudeOutcome,
        Path implementationDirectory,
        String failureReason,
        Map<String, String> resolvedVersionsByCoordinates,
        PlanConformanceResult planConformance) {

    public ImplementationOutcome {
        Objects.requireNonNull(change, "change");
        Objects.requireNonNull(claudeOutcome, "claudeOutcome");
        Objects.requireNonNull(implementationDirectory, "implementationDirectory");
        resolvedVersionsByCoordinates = resolvedVersionsByCoordinates == null
                ? Map.of() : Map.copyOf(resolvedVersionsByCoordinates);
    }

    /**
     * Legacy-arity constructor for every caller that predates plan conformance -- defaults
     * {@code planConformance} to {@code null}, meaning "no approved plan was in play," which is exactly
     * what a {@code null} means everywhere else this field is read.
     */
    public ImplementationOutcome(
            String runId, String unitId, String coordinates, String branchName, ImplementationReport report,
            ChangeOutcome change, ValidationOutcome validation, ValidationOutcome fullBuildValidation,
            ClaudeRunOutcome claudeOutcome, Path implementationDirectory, String failureReason,
            Map<String, String> resolvedVersionsByCoordinates) {
        this(runId, unitId, coordinates, branchName, report, change, validation, fullBuildValidation,
                claudeOutcome, implementationDirectory, failureReason, resolvedVersionsByCoordinates, null);
    }

    public boolean hasReport() {
        return report != null;
    }

    /** {@code null} when the gate was never consulted, which is every path that was undone regardless. */
    public boolean wasValidated() {
        return validation != null;
    }

    /** {@code null} when there was no commit for the full build to check. */
    public boolean fullBuildRan() {
        return fullBuildValidation != null;
    }

    /** Committed, and the full build then confirmed it -- the only state that counts as fully done. */
    public boolean fullyBuildValidated() {
        return fullBuildValidation != null && fullBuildValidation.status() == ValidationStatus.PASSED;
    }

    public boolean committed() {
        return change.committed();
    }

    public ChangeDisposition disposition() {
        return change.disposition();
    }

    /** True when the implementation deliberately stopped because the branch disproved the assessment. */
    public boolean stoppedOnContradiction() {
        return report != null
                && report.conclusion() == ImplementationConclusion.STOPPED_ASSESSMENT_CONTRADICTED;
    }
}
