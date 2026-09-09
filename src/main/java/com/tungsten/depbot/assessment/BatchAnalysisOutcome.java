package com.tungsten.depbot.assessment;

import com.tungsten.depbot.claude.ClaudeRunOutcome;

import java.nio.file.Path;
import java.util.Objects;

/**
 * What one whole-batch Vulnerability Analysis Engineer call produced: the analysis document when there
 * is one, {@code status}'s own explicit classification, and where everything was written.
 *
 * <p>{@code analysis} is non-null only when {@code status} is {@link BatchAnalysisStatus#COMPLETE} --
 * for {@link BatchAnalysisStatus#FAILED} (Claude failed, or every attempt to produce a document failed
 * to parse or validate for a reason other than running out of turns or time), {@link
 * BatchAnalysisStatus#INCOMPLETE} (the second attempt produced a document, but
 * {@link AnalysisCoverageValidator} refused to trust it), and {@link BatchAnalysisStatus#PARTIAL} (both
 * attempts ran out of turns or time -- see {@code partialAnalysisState}), routing must not treat this
 * outcome as a real verdict about any finding. The three are nonetheless handled differently by
 * {@code VulnerabilityRemediationService}: {@code FAILED} routes every finding to Human Review Engineer
 * individually; {@code INCOMPLETE} stops the whole run before touching any finding at all; {@code PARTIAL}
 * hands each finding to a constrained Remediation Engineer fallback (or Human Review, when even that
 * cannot determine a direction) -- none of the three is ever masked as a normal Human Review outcome nor
 * as "nothing needs remediating."
 */
public record BatchAnalysisOutcome(
        String runId,
        BatchAnalysis analysis,
        BatchAnalysisStatus status,
        String incompleteReason,
        PartialAnalysisState partialAnalysisState,
        ClaudeRunOutcome claudeOutcome,
        Path analysisDirectory) {

    public BatchAnalysisOutcome {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(claudeOutcome, "claudeOutcome");
        Objects.requireNonNull(analysisDirectory, "analysisDirectory");
    }

    /** A validated, routable {@link BatchAnalysis} was produced. */
    public boolean hasAnalysis() {
        return status == BatchAnalysisStatus.COMPLETE;
    }

    /** See {@link BatchAnalysisStatus#INCOMPLETE}. {@code incompleteReason()} names why, when this is true. */
    public boolean isIncomplete() {
        return status == BatchAnalysisStatus.INCOMPLETE;
    }

    /** See {@link BatchAnalysisStatus#PARTIAL}. {@code partialAnalysisState()} carries what survived, when this is true. */
    public boolean isPartial() {
        return status == BatchAnalysisStatus.PARTIAL;
    }
}
