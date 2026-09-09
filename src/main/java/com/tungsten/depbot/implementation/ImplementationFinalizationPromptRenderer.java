package com.tungsten.depbot.implementation;

import com.tungsten.depbot.report.SecretRedactor;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Renders the short, report-only prompt used only after an implementation ran out of turns or time.
 *
 * <p>This is not a second attempt at the remediation, and it is not investigation either: this call has
 * no tools at all ({@link com.tungsten.depbot.claude.ClaudeToolPolicy#forImplementationFinalization()}).
 * Java precomputes exactly what has actually changed on the branch -- {@code git status --porcelain},
 * {@code git diff --stat} and the full {@code git diff}, all against this group's own accepted
 * cumulative starting point -- and embeds it verbatim in the prompt below, so there is nothing left for
 * Claude to spend a turn discovering. This is the fix for a real production failure: a finalization call
 * that was told to run {@code git diff}/{@code git status} itself burned its whole turn budget on tool
 * calls and never emitted a report at all.
 *
 * <p>Every piece of Mend-authored text passes through a {@link SecretRedactor}, for the same reason
 * {@link ImplementationPromptRenderer} does: this prompt is written to disk as {@code prompt.md}.
 */
public final class ImplementationFinalizationPromptRenderer {

    /** The literal every finalization prompt starts with -- distinct from either phase's own marker. */
    public static final String FINALIZATION_MARKER = "<!-- depbot-finalization:IMPLEMENTATION -->";

    private static final String NO_OUTPUT = "(no output -- nothing to show)";

    private final SecretRedactor redactor;

    /** A renderer that knows no secrets. Only for callers that genuinely hold none. */
    public ImplementationFinalizationPromptRenderer() {
        this(SecretRedactor.none());
    }

    public ImplementationFinalizationPromptRenderer(SecretRedactor redactor) {
        this.redactor = Objects.requireNonNull(redactor, "redactor");
    }

    /**
     * @param context             the same branch and context the original implementation call was given
     * @param resumingSameSession whether this call resumes the session that ran out of room, and so
     *                            already has its own reasoning about the change in context
     * @param gitStatusShort      Java's own {@code git status --porcelain} of the branch, right now
     * @param gitDiff             Java's own {@code git diff <branchBaseSha>} of the branch, right now
     * @param gitDiffStat         Java's own {@code git diff --stat <branchBaseSha>} of the branch, right now
     */
    public String render(
            ImplementationContext context, boolean resumingSameSession,
            String gitStatusShort, String gitDiff, String gitDiffStat) {
        Objects.requireNonNull(context, "context");

        List<String> lines = new ArrayList<>();
        lines.add(FINALIZATION_MARKER);
        lines.add("");
        lines.add("# Implementation time is over -- report on what is actually there now");
        lines.add("");
        lines.add("You are past the turn or time budget for implementing this remediation for "
                + context.coordinates() + ". No further edits happen in this call, and no new "
                + "investigation happens either: **you have no tools at all in this call.** Everything "
                + "you need to answer honestly is already below -- the actual state of branch `"
                + context.branchName() + "` at " + context.workspace() + ", already gathered for you.");
        lines.add("");

        if (resumingSameSession) {
            lines.add("This continues the session you were already implementing in. Everything you "
                    + "already changed and reasoned about is still available to you here. The evidence "
                    + "below is the same branch state, gathered independently -- use it to check your own "
                    + "memory of what you did, not the other way around. Do not make any further edits.");
        } else {
            lines.add("The earlier attempt at this could not be resumed, so this call has no memory of "
                    + "any of it. The evidence below -- gathered directly from the branch, not from "
                    + "anything said before -- is everything you have to work from. Do not invent changes "
                    + "you cannot see in it.");
        }
        lines.add("");

        lines.add("## What is actually on this branch right now");
        lines.add("");
        lines.add("`git status --porcelain`:");
        lines.add("");
        lines.add("```text");
        lines.add(blockOrNone(gitStatusShort));
        lines.add("```");
        lines.add("");
        lines.add("`git diff --stat " + context.branchBaseSha() + "`:");
        lines.add("");
        lines.add("```text");
        lines.add(blockOrNone(gitDiffStat));
        lines.add("```");
        lines.add("");
        lines.add("`git diff " + context.branchBaseSha() + "`:");
        lines.add("");
        lines.add("```diff");
        lines.add(blockOrNone(gitDiff));
        lines.add("```");
        lines.add("");

        lines.add("## What to do");
        lines.add("");
        lines.add("Look at the evidence above and report honestly:");
        lines.add("");
        lines.add("- If the remediation is genuinely finished -- the change is there, complete and "
                + "correct as far as you can tell -- say so: `conclusion` of `COMPLETED`, with "
                + "`changesMade` listing what is actually there.");
        lines.add("- If it is not finished, or you cannot be confident it is, say that instead: "
                + "`conclusion` of `STOPPED_BLOCKED`, with `remainingWork` and/or `risks` stating plainly "
                + "what is missing or unconfirmed. This is the honest, correct answer when time ran out "
                + "before the work did -- it is not a failure, and it is far more useful than no report "
                + "at all: a partial, honestly-described change lets a person pick up exactly where you "
                + "left off, instead of finding nothing.");
        lines.add("- Do not report `COMPLETED` just because a diff exists above. An unconfident "
                + "`COMPLETED` gets exactly as much scrutiny as any other report -- the bot still checks "
                + "the diff, the dependency resolution, the full build and Jenkins before trusting it -- "
                + "so overstating this has no benefit and a real cost: a validated-looking commit that is "
                + "not actually finished.");
        lines.add("");
        lines.add("End your answer with a single fenced `json` block containing exactly the same document "
                + "the original implementation call was asked for, and nothing after it:");
        lines.add("");
        lines.add("```json");
        lines.add(ImplementationPromptRenderer.OUTPUT_SCHEMA);
        lines.add("```");
        lines.add("");
        lines.add("`coordinates`, `conclusion`, `summary` and `observedState` are always required, exactly "
                + "as before. Leave anything you cannot establish out rather than filling it in to look "
                + "complete.");

        return redactor.redact(String.join("\n", lines) + "\n");
    }

    private static String blockOrNone(String value) {
        return (value == null || value.isBlank()) ? NO_OUTPUT : value.strip();
    }
}
