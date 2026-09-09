package com.tungsten.depbot.assessment;

import com.tungsten.depbot.report.SecretRedactor;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Renders the short, report-only prompt used only after a whole-batch analysis ran out of turns or
 * time.
 *
 * <p>Same principle as the per-finding {@link AssessmentFinalizationPromptRenderer} this replaces: not a
 * second investigation, no tools offered at all, write down the engineering conclusions from whatever
 * is already known. The one thing that changes at batch scale is what "already known" must cover: every
 * finding in the batch needs an honest answer, not just the ones reached before time ran out. A finding
 * this call still cannot reach must come back {@code INCONCLUSIVE} with {@code risks} saying so -- it
 * must never simply be missing from the answer, which is indistinguishable from a silent drop.
 */
public final class BatchAnalysisFinalizationPromptRenderer {

    /** The literal every finalization prompt starts with -- distinct from either phase's own marker. */
    public static final String FINALIZATION_MARKER = "<!-- depbot-finalization:ASSESSMENT -->";

    private final SecretRedactor redactor;
    private final FindingContextRenderer findingRenderer;

    /** A renderer that knows no secrets. Only for callers that genuinely hold none. */
    public BatchAnalysisFinalizationPromptRenderer() {
        this(SecretRedactor.none());
    }

    public BatchAnalysisFinalizationPromptRenderer(SecretRedactor redactor) {
        this.redactor = Objects.requireNonNull(redactor, "redactor");
        this.findingRenderer = new FindingContextRenderer(redactor);
    }

    /**
     * @param context             the same batch the original analysis was given
     * @param resumingSameSession whether this call resumes the session that ran out of room, and so
     *                            already has its own investigation in context
     */
    public String render(AnalysisContext context, boolean resumingSameSession) {
        Objects.requireNonNull(context, "context");
        List<VulnerabilityWorkItem> workItems = context.workItems();

        List<String> lines = new ArrayList<>();
        lines.add(FINALIZATION_MARKER);
        lines.add("");
        lines.add("# Investigation time is over -- write your analysis now");
        lines.add("");
        lines.add("You are past the turn or time budget for investigating this batch of " + workItems.size()
                + (workItems.size() == 1 ? " finding" : " findings") + ". No further investigation happens "
                + "in this call: **no tools are available to you here at all**, not even reading a file. "
                + "This is not a penalty -- it is simply the point where a real engineer has to write up "
                + "what they know rather than keep digging.");
        lines.add("");

        if (resumingSameSession) {
            lines.add("This continues the session you were already investigating in. Everything you had "
                    + "already established -- what you read, what you ran, what you concluded so far, for "
                    + "every finding you reached -- is still available to you here. Do not repeat or "
                    + "re-derive any of it; just state it.");
            lines.add("");
        } else {
            lines.add("The earlier attempt at this could not be resumed, so this call has no memory of any "
                    + "investigation that happened. All you have is every finding as Mend reported it, "
                    + "below. Do not invent findings, files or history you cannot see from here.");
            lines.add("");
            for (int i = 0; i < workItems.size(); i++) {
                lines.add("## Finding " + (i + 1) + " of " + workItems.size() + ": "
                        + workItems.get(i).coordinates());
                lines.add("");
                findingRenderer.appendTo(lines, workItems.get(i));
            }
        }

        lines.add("## What to do");
        lines.add("");
        lines.add("Write your best-effort engineering analysis from what you actually have. For every "
                + "finding you established enough about to conclude it needs remediation or does not apply, "
                + "say so plainly, exactly as the original analysis would have -- including forming and "
                + "describing a remediation group for any `REMEDIATION_REQUIRED` finding, exactly as the "
                + "original call would have. **For any finding you did not get far enough to reach at all,** "
                + "answer `INCONCLUSIVE` for it and use `risks` to state specifically that time or turns ran "
                + "out before it was looked at -- that is a complete, correct answer for that finding, not a "
                + "failure. A finding must never simply be left out of your answer: that is indistinguishable "
                + "from having silently dropped it. Never fill a gap with a guess just because you are out "
                + "of room to check it.");
        lines.add("");
        lines.add("End your answer with a single fenced `json` block containing exactly the same document "
                + "the original analysis asked for, covering every finding above, and nothing after it:");
        lines.add("");
        lines.add("```json");
        lines.add(BatchAnalysisPromptRenderer.OUTPUT_SCHEMA);
        lines.add("```");
        lines.add("");
        lines.add("Anything you could not establish: omit the field, or set it to `null` or an empty list, "
                + "exactly as before.");

        return redactor.redact(String.join("\n", lines) + "\n");
    }
}
