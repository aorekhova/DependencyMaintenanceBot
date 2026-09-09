package com.tungsten.depbot.publication;

/** See {@link CohortRepositoryPreflight}. {@code expectedTip} is set only when {@code ok} is true. */
public record PreflightResult(boolean ok, String reason, String expectedTip) {

    public static PreflightResult ok(String expectedTip) {
        return new PreflightResult(true, null, expectedTip);
    }

    public static PreflightResult failed(String reason) {
        return new PreflightResult(false, reason, null);
    }
}
