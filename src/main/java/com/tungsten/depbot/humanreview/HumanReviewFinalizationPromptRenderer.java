package com.tungsten.depbot.humanreview;

import com.tungsten.depbot.report.SecretRedactor;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Renders the short, report-only prompt used only after a Human Review Engineer call ran out of turns
 * or time.
 *
 * <p>Zero-tool, the same shape as {@code AssessmentFinalizationPromptRenderer} rather than the
 * read-only {@code ImplementationFinalizationPromptRenderer}: Human Review never edits anything, so
 * there is no "what's actually on disk" fact only a tool call could reveal by the time finalization is
 * reached -- the job is purely to write up what the primary call (or its own already-bounded follow-up
 * investigation) already established.
 *
 * <p><strong>When the primary session cannot be resumed, this call has zero tools and zero memory of
 * its own -- the bot's own saved {@link HumanReviewContext} is the only thing it can possibly work
 * from.</strong> That context already carries everything the Vulnerability Analysis Engineer worked
 * out (the group's members/companions, grouping reason, source ref, evidence/risks, recommended
 * remediation and target version, implementation/validation plans, and the automation decision and its
 * reason) -- so that call must actually restate all of it, not merely claim to. Reuses the exact same
 * context-rendering methods {@link HumanReviewPromptRenderer} uses for the primary call, so the two
 * documents describe the same facts the same way and nothing here can drift out of sync with what the
 * primary prompt already says.
 */
public final class HumanReviewFinalizationPromptRenderer {

    /** The literal every finalization prompt starts with -- distinct from either phase's own marker. */
    public static final String FINALIZATION_MARKER = "<!-- depbot-finalization:HUMAN_REVIEW -->";

    private final SecretRedactor redactor;
    private final HumanReviewPromptRenderer contextRenderer;

    /** A renderer that knows no secrets. Only for callers that genuinely hold none. */
    public HumanReviewFinalizationPromptRenderer() {
        this(SecretRedactor.none());
    }

    public HumanReviewFinalizationPromptRenderer(SecretRedactor redactor) {
        this.redactor = Objects.requireNonNull(redactor, "redactor");
        this.contextRenderer = new HumanReviewPromptRenderer(redactor);
    }

    /**
     * @param context             the same context the original review call was given
     * @param resumingSameSession whether this call resumes the session that ran out of room
     */
    public String render(HumanReviewContext context, boolean resumingSameSession) {
        Objects.requireNonNull(context, "context");

        List<String> lines = new ArrayList<>();
        lines.add(FINALIZATION_MARKER);
        lines.add("");
        lines.add("# Investigation time is over -- write your human review report now");
        lines.add("");
        lines.add("You are past the turn or time budget for reviewing " + context.coordinates() + ". No "
                + "further investigation happens in this call: **no tools are available to you here at "
                + "all**, not even reading a file.");
        lines.add("");

        if (resumingSameSession) {
            lines.add("This continues the session you were already investigating in. Everything you had "
                    + "already established is still available to you here. Do not repeat or re-derive any "
                    + "of it; just state it.");
            lines.add("");
        } else {
            lines.add("The earlier attempt at this could not be resumed, so this call has no memory of any "
                    + "investigation that happened. Everything the Vulnerability Analysis Engineer already "
                    + "established -- and, if this call's own earlier investigation got anywhere before "
                    + "running out of room, whatever of that survived -- is restated below. Work from that; "
                    + "do not treat it as unavailable just because you cannot remember establishing it "
                    + "yourself.");
            lines.add("");
            contextRenderer.appendFindings(lines, context);
            contextRenderer.appendGroupPlan(lines, context.group());
            HumanReviewPromptRenderer.appendCompanions(lines, context);
            contextRenderer.appendFailureContext(lines, context);
        }

        lines.add("## What to do");
        lines.add("");
        lines.add("Write your best-effort human review report from what you actually have. Where you did "
                + "not get far enough to answer one of the six fixed questions, say so plainly in "
                + "`openQuestions` -- that is a complete, correct answer, not a failure. Never fill a gap "
                + "with a guess just because you are out of room to check it.");
        lines.add("");
        lines.add("End your answer with a single fenced `json` block containing exactly the same document "
                + "the original call asked for, and nothing after it:");
        lines.add("");
        lines.add("```json");
        lines.add(HumanReviewPromptRenderer.OUTPUT_SCHEMA);
        lines.add("```");

        return redactor.redact(String.join("\n", lines) + "\n");
    }
}
