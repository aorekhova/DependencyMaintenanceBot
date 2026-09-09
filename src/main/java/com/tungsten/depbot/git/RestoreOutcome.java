package com.tungsten.depbot.git;

/**
 * Whether the checkout was safely returned to its original state.
 *
 * <p>{@code safeMessage} is set only when {@code restored} is {@code false}: the checkout was
 * left as-is (never forced), and this explains why and what to do about it.
 */
public record RestoreOutcome(boolean restored, String safeMessage) {

    public static RestoreOutcome success() {
        return new RestoreOutcome(true, null);
    }

    public static RestoreOutcome unsafe(String safeMessage) {
        return new RestoreOutcome(false, safeMessage);
    }
}
