package com.tungsten.depbot.assessment;

import com.tungsten.depbot.report.SecretRedactor;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Renders the short, tool-free, bounded prompt used exactly once when a whole-batch Vulnerability
 * Analysis call itself completed normally -- a real, substantive investigation, not a timeout or
 * {@code error_max_turns} -- but its final machine-readable document could not be parsed, bound, or
 * structurally validated (a missing required field, an invalid enum value, a malformed JSON wrapper).
 *
 * <p>This is deliberately narrower than {@link BatchAnalysisFinalizationPromptRenderer}: that one exists
 * because investigation time genuinely ran out and some findings may never have been reached at all, so
 * it walks through every finding again and allows fresh {@code INCONCLUSIVE} answers. This one exists
 * because the investigation is already complete and the substantive conclusions are already trusted --
 * the only defect is in how the final document was written down. It never re-lists the findings, never
 * asks Claude to reconsider a conclusion, and is not a second investigation attempt or a new role: it is
 * the same Vulnerability Analysis Engineer, asked to repair its own document's shape and nothing else.
 *
 * <p>Exactly one such call is ever made per batch (see {@code BatchAnalysisService}) -- if the repaired
 * document is still unusable, the existing unusable-analysis/Human Review fallback applies, never a
 * second repair attempt.
 */
public final class BatchAnalysisSchemaRepairPromptRenderer {

    /** The literal every schema-repair prompt starts with -- distinct from every other call shape. */
    public static final String SCHEMA_REPAIR_MARKER = "<!-- depbot-schema-repair:ASSESSMENT -->";

    private final SecretRedactor redactor;

    /** A renderer that knows no secrets. Only for callers that genuinely hold none. */
    public BatchAnalysisSchemaRepairPromptRenderer() {
        this(SecretRedactor.none());
    }

    public BatchAnalysisSchemaRepairPromptRenderer(SecretRedactor redactor) {
        this.redactor = Objects.requireNonNull(redactor, "redactor");
    }

    /**
     * @param resumingSameSession whether this call resumes the session that produced the malformed
     *                            document, and so already has its own conclusions in context
     * @param previousAnswerText  the previous call's own last message, exactly as it wrote it -- used
     *                            only when the session cannot be resumed, so this call still has
     *                            something concrete to repair rather than nothing at all; may be
     *                            {@code null} when even that was not captured
     * @param parseErrorDetail    the exact parser/validation error naming what is structurally wrong
     *                            (e.g. a missing field or an unrecognised value) -- never the surrounding
     *                            answer text itself
     */
    public String render(boolean resumingSameSession, String previousAnswerText, String parseErrorDetail) {
        Objects.requireNonNull(parseErrorDetail, "parseErrorDetail");

        List<String> lines = new ArrayList<>();
        lines.add(SCHEMA_REPAIR_MARKER);
        lines.add("");
        lines.add("# Your analysis was substantive -- only its final document could not be read");
        lines.add("");
        lines.add("Your investigation of this batch already completed. The problem is not with your "
                + "conclusions -- it is that the final machine-readable JSON document you returned could "
                + "not be parsed or validated against the required output schema. **This is not a request "
                + "to investigate anything further: no tools are available to you here at all.**");
        lines.add("");
        lines.add("The exact error was:");
        lines.add("");
        lines.add("```");
        lines.add(parseErrorDetail);
        lines.add("```");
        lines.add("");
        if (resumingSameSession) {
            lines.add("This continues your own session, so everything you already established -- every "
                    + "finding, every remediation group, every plan -- is still available to you here. Do "
                    + "not repeat or re-derive any of it.");
        } else if (previousAnswerText != null && !previousAnswerText.isBlank()) {
            lines.add("The earlier session could not be resumed, so this call has no memory of the "
                    + "investigation itself. Your own previous answer, exactly as you wrote it, was:");
            lines.add("");
            lines.add("```");
            lines.add(previousAnswerText);
            lines.add("```");
        } else {
            lines.add("Neither the earlier session nor its own previous answer text could be recovered. "
                    + "State your best-effort conclusions for this batch, exactly as your original analysis "
                    + "would have, in the corrected document shape below.");
        }
        lines.add("");
        lines.add("## What to do");
        lines.add("");
        lines.add("Do not redo vulnerability research. Do not change substantive conclusions, grouping, "
                + "targets, risk decisions, evidence or remediation direction unless required solely to "
                + "make the document internally consistent. Repair the machine-readable final document and "
                + "return the corrected final JSON only.");
        lines.add("");
        lines.add("The required document shape (every field, exactly as your original analysis was asked "
                + "for -- in particular, every `plannedChanges` entry needs an explicit `changeType`, one "
                + "of `VERSION_BUMP`, `DEPENDENCY_MANAGEMENT_ADDITION`, `EXCLUSION_ADDED`, or `OTHER` with "
                + "a concrete `reason` -- never omitted):");
        lines.add("");
        lines.add("```json");
        lines.add(BatchAnalysisPromptRenderer.OUTPUT_SCHEMA);
        lines.add("```");
        lines.add("");
        lines.add("End your answer with a single fenced `json` block containing exactly this corrected "
                + "document, and nothing after it.");

        return redactor.redact(String.join("\n", lines) + "\n");
    }
}
