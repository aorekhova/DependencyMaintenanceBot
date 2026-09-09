package com.tungsten.depbot.claude;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds the structured document inside a model's free-text answer.
 *
 * <p>Both roles answer the same way: a developer's write-up in prose, ending with the document that
 * commits to a conclusion. Both parts matter -- the prose is what makes the saved artifact reviewable
 * -- so neither phase demands an answer that is nothing but JSON.
 *
 * <p>The <em>last</em> complete object wins, preferring one inside a fenced block. Last, not first,
 * because a write-up that quotes an intermediate or illustrative object before committing to its final
 * answer would otherwise be read at its earliest guess.
 *
 * <p>The scan tracks string literals and their escapes, so a brace inside a quoted value -- a path, a
 * version range, a property placeholder, a diff fragment -- never ends an object early. That is the
 * one part of this worth sharing rather than writing twice.
 */
public final class JsonAnswerExtractor {

    /**
     * A fenced block, with or without a language tag. Reluctant, so consecutive blocks are matched
     * individually rather than as one span from the first opening fence to the last closing one.
     */
    private static final Pattern FENCED_BLOCK = Pattern.compile(
            "```[ \\t]*[A-Za-z0-9_+-]*[ \\t]*\\R(.*?)```", Pattern.DOTALL);

    private JsonAnswerExtractor() {
    }

    /** @return the last complete JSON object in {@code answerText}, or {@code null} if there is none */
    public static String lastJsonObject(String answerText) {
        if (answerText == null || answerText.isBlank()) {
            return null;
        }

        String fromFence = null;
        Matcher matcher = FENCED_BLOCK.matcher(answerText);
        while (matcher.find()) {
            String candidate = lastBalancedObject(matcher.group(1));
            if (candidate != null) {
                fromFence = candidate;
            }
        }
        return fromFence != null ? fromFence : lastBalancedObject(answerText);
    }

    private static String lastBalancedObject(String text) {
        String last = null;
        int depth = 0;
        int start = -1;
        boolean inString = false;
        boolean escaped = false;

        for (int i = 0; i < text.length(); i++) {
            char character = text.charAt(i);

            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (character == '\\') {
                    escaped = true;
                } else if (character == '"') {
                    inString = false;
                }
                continue;
            }

            switch (character) {
                case '"' -> inString = true;
                case '{' -> {
                    if (depth == 0) {
                        start = i;
                    }
                    depth++;
                }
                case '}' -> {
                    if (depth > 0) {
                        depth--;
                        if (depth == 0) {
                            last = text.substring(start, i + 1);
                        }
                    }
                }
                default -> {
                    // Nothing outside a string or a brace affects where an object begins or ends.
                }
            }
        }
        return last;
    }
}
