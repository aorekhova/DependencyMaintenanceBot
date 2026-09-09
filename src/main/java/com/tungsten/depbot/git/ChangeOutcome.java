package com.tungsten.depbot.git;

import java.util.List;

/**
 * What became of one implementation's changes, and the diff itself so a caller can preserve it.
 *
 * <p>{@code patch} is carried out rather than written here because deciding <em>where</em> an artifact
 * belongs is the phase service's business, not the committer's. It is populated even when the change
 * was rolled back: a rejected diff is the single most useful thing to look at afterwards, and it is
 * gone from the working tree by the time anyone could ask.
 *
 * <p>{@code reason} is meant to be read by a person or handed to Claude as prompt context -- it is
 * always a short, clean, bot-composed sentence, never raw command output. {@code diagnosticDetail} is
 * the opposite: {@code null} in the overwhelming majority of outcomes, and populated only for the one
 * known case where a git command's own raw error text (which can include local filesystem paths) is
 * worth keeping for troubleshooting -- a tolerated, non-fatal {@code git clean -fd} failure during
 * rollback. It belongs only in internal diagnostic artifacts, never in {@code reason} itself.
 */
public record ChangeOutcome(
        ChangeDisposition disposition,
        String commitSha,
        String patch,
        List<String> policyViolations,
        String reason,
        String diagnosticDetail) {

    public ChangeOutcome {
        patch = patch == null ? "" : patch;
        policyViolations = policyViolations == null ? List.of() : List.copyOf(policyViolations);
    }

    public boolean committed() {
        return disposition == ChangeDisposition.COMMITTED_PENDING_VALIDATION;
    }
}
