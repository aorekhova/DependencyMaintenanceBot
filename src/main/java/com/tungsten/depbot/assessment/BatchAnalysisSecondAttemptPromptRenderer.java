package com.tungsten.depbot.assessment;

import com.tungsten.depbot.report.SecretRedactor;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Renders the second Vulnerability Analysis attempt's prompt -- run only when the first ran out of
 * turns or time.
 *
 * <p><strong>This is not the old report-only finalization.</strong> The second attempt keeps the same
 * tools and the same freedom to investigate as the first ({@code ClaudeToolPolicy.forPhase(ASSESSMENT)}):
 * it is asked to <em>continue</em> the investigation with a smaller budget, not to stop investigating and
 * write up whatever is already known. When the first attempt's session can be resumed, everything it had
 * already established is still there in context -- this prompt then only has to say what has changed
 * (a smaller budget now) and ask for focus on whatever is still open, never to repeat work already done.
 * When it cannot be resumed, this call has no memory of the first attempt at all, and is told so plainly,
 * the same way the original prompt would be -- but still with its investigative tools intact.
 */
public final class BatchAnalysisSecondAttemptPromptRenderer {

    /** The literal every second-attempt prompt starts with -- distinct from the primary and finalization markers. */
    public static final String SECOND_ATTEMPT_MARKER = "<!-- depbot-second-attempt:ASSESSMENT -->";

    private final SecretRedactor redactor;
    private final FindingContextRenderer findingRenderer;

    /** A renderer that knows no secrets. Only for callers that genuinely hold none. */
    public BatchAnalysisSecondAttemptPromptRenderer() {
        this(SecretRedactor.none());
    }

    public BatchAnalysisSecondAttemptPromptRenderer(SecretRedactor redactor) {
        this.redactor = Objects.requireNonNull(redactor, "redactor");
        this.findingRenderer = new FindingContextRenderer(redactor);
    }

    /**
     * @param context               the same batch the first attempt was given
     * @param resumingSameSession   whether this call resumes the session that ran out of room, and so
     *                              already has its own investigation in context
     * @param firstAttemptRawText   whatever text the first attempt's own process actually produced before
     *                              it ran out of room, when it is known and {@code resumingSameSession} is
     *                              {@code false} -- {@code null}/blank when nothing survived (a genuine
     *                              wall-clock kill leaves no output at all) or when resuming makes it
     *                              redundant to restate
     */
    public String render(AnalysisContext context, boolean resumingSameSession, String firstAttemptRawText) {
        Objects.requireNonNull(context, "context");
        List<VulnerabilityWorkItem> workItems = context.workItems();

        List<String> lines = new ArrayList<>();
        lines.add(SECOND_ATTEMPT_MARKER);
        lines.add("");
        lines.add("# Second Vulnerability Analysis attempt -- continue, do not restart");
        lines.add("");
        lines.add("You are the same Vulnerability Analysis Engineer, on the same batch of " + workItems.size()
                + (workItems.size() == 1 ? " finding" : " findings") + ". Your first attempt at this ran out "
                + "of its turn or time budget before finishing. This is not a penalty and not a report-only "
                + "write-up call -- **you still have your full investigative tools** (the same shell, file "
                + "and web access you had before). You have a smaller turn and time budget this time, so "
                + "spend it continuing the investigation efficiently, not repeating work you have already "
                + "done.");
        lines.add("");

        if (resumingSameSession) {
            lines.add("This continues the session you were already investigating in. Everything you had "
                    + "already established -- what you read, what you ran, what you concluded so far, for "
                    + "every finding you reached -- is still available to you here. Do not re-derive or "
                    + "re-investigate any of it. Spend your reduced budget on whatever is still genuinely "
                    + "open: findings you had not reached yet, or loose ends in ones you had.");
            lines.add("");
        } else {
            lines.add("The first attempt's session could not be resumed, so this call has no memory of "
                    + "whatever investigation already happened -- " + (firstAttemptRawText == null
                            || firstAttemptRawText.isBlank()
                            ? "and nothing it produced survived to hand you either."
                            : "but here is the last thing it actually wrote, in case any of it is useful:"));
            lines.add("");
            if (firstAttemptRawText != null && !firstAttemptRawText.isBlank()) {
                lines.add("## What the first attempt last wrote, before it ran out of room");
                lines.add("");
                lines.add("> This is raw, unverified output from the earlier attempt -- treat it as a lead "
                        + "to check, never as an established fact.");
                lines.add("");
                lines.add(firstAttemptRawText.strip());
                lines.add("");
            }
            lines.add("All you otherwise have is every finding as Mend reported it, below, exactly as the "
                    + "first attempt started with. Do not invent findings, files or history you cannot see "
                    + "from here. You have a smaller budget than the first attempt did, so work efficiently.");
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
        lines.add("Investigate freely, exactly as the first attempt was asked to -- nothing here prescribes "
                + "an order, a set of commands or which files to look at, and nothing prescribes how many "
                + "findings should end up sharing a remediation group. Reach a genuine engineering "
                + "conclusion for every finding you can. **A finding must never simply be left out of your "
                + "answer** -- for any finding you genuinely cannot reach or resolve even with this second "
                + "attempt, answer `INCONCLUSIVE` for it and use `risks` to say plainly that it was not "
                + "examined and why, so that fact is honest and visible rather than silently dropped.");
        lines.add("");
        lines.add("End your answer with a single fenced `json` block containing exactly the same document "
                + "the first attempt was asked for, covering every finding above, and nothing after it:");
        lines.add("");
        lines.add("```json");
        lines.add(BatchAnalysisPromptRenderer.OUTPUT_SCHEMA);
        lines.add("```");

        return redactor.redact(String.join("\n", lines) + "\n");
    }
}
