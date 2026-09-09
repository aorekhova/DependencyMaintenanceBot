package com.tungsten.depbot.claude;

import java.util.List;
import java.util.Locale;

/**
 * Recognises "this account cannot use that model" among the other reasons Claude Code can fail.
 *
 * <p>This exists purely so the operator gets a message that names the real problem. It has no
 * effect on what runs: whether or not the phrase is recognised, the unit fails and no other model
 * is ever tried. A missed phrase costs a clear explanation, never a silent downgrade.
 */
public final class ModelAvailability {

    private static final List<String> UNAVAILABLE_PHRASES = List.of(
            "model not found",
            "model_not_found",
            "invalid model",
            "unknown model",
            "unsupported model",
            "model is not available",
            "model not available",
            "does not have access to",
            "not authorized to use",
            "no access to model");

    private ModelAvailability() {
    }

    /** True when the process output reads like a model-permission or unknown-model rejection. */
    public static boolean looksUnavailable(String stdout, String stderr) {
        String combined = ((stdout == null ? "" : stdout) + "\n" + (stderr == null ? "" : stderr))
                .toLowerCase(Locale.ROOT);
        return UNAVAILABLE_PHRASES.stream().anyMatch(combined::contains);
    }

    /** Explains the failure and, just as importantly, states what was deliberately not done. */
    public static String unavailableMessage(String model) {
        return "Claude Code rejected the model \"" + model + "\" -- this account does not appear to have "
                + "access to it. No weaker model was substituted, because a downgraded model would "
                + "silently produce a lower-quality upgrade. Grant the account access to \"" + model
                + "\", or set " + ClaudeConfig.CLAUDE_MODEL + " deliberately to a model it can use.";
    }
}
