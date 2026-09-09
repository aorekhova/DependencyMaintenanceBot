package com.tungsten.depbot.git;

/**
 * Whether the orchestrator managed to bring local remote-tracking refs up to date.
 *
 * <p>{@code refreshed} is not a mere formality: it is asserted to the assessment in its prompt. An
 * assessment told that {@code origin/*} is current when it is not would conclude that a branch does
 * not exist because it was never fetched, which is the same class of wrong answer the whole two-phase
 * design exists to stop.
 */
public record RefsRefreshOutcome(boolean refreshed, String message) {

    public static RefsRefreshOutcome refreshed(String remote) {
        return new RefsRefreshOutcome(true, "Refreshed every branch and tag from " + remote + ".");
    }

    public static RefsRefreshOutcome failed(String safeMessage) {
        return new RefsRefreshOutcome(false, safeMessage);
    }
}
