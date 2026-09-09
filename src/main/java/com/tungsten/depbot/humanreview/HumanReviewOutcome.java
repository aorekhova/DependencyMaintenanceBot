package com.tungsten.depbot.humanreview;

import com.tungsten.depbot.claude.ClaudeRunOutcome;

import java.nio.file.Path;
import java.util.Objects;

/**
 * What one Human Review Engineer call produced: the report when there is one, and where everything was
 * written. No change/validation/build fields -- there is nothing here to validate or build, since this
 * role never edits anything.
 */
public record HumanReviewOutcome(
        String runId,
        String unitId,
        String coordinates,
        HumanReviewReport report,
        ClaudeRunOutcome claudeOutcome,
        Path humanReviewDirectory,
        String failureReason) {

    public HumanReviewOutcome {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(unitId, "unitId");
        Objects.requireNonNull(claudeOutcome, "claudeOutcome");
        Objects.requireNonNull(humanReviewDirectory, "humanReviewDirectory");
    }

    public boolean hasReport() {
        return report != null;
    }
}
