package com.tungsten.depbot.progress;

/**
 * Told when each step starts and finishes, so a long run says what it is doing while it does it.
 *
 * <p>Separate from the reporting that happens after a library finishes. That reporting is a summary and
 * arrives too late to be of any use while a Claude call is running: a pilot can sit for ten minutes with
 * nothing on screen, and there is no way to tell a working run from a stuck one.
 *
 * <p>Deliberately two required methods and an enum rather than a method per step. A listener should not
 * have to be edited every time a step is added, and a step that nobody thought to add a callback for
 * would silently stop reporting -- which is the failure this exists to prevent. One further, optional
 * method exists for the same reason a third state exists on this project's other enums: a step whose
 * duration cannot be predicted needs a way to say "still working" without becoming a method added per
 * {@link RemediationStep} value -- {@link #stepHeartbeat} is one additional kind of event across every
 * step, keyed by the same enum, not new surface area per step.
 *
 * <p>Implementations must not throw. Progress reporting is not allowed to break a run.
 */
public interface RemediationProgressListener {

    /**
     * @param detail extra context, or {@code null}. Must be safe to print: a ref, a branch, a count --
     *               never a credential, an environment value or file content
     */
    void stepStarting(RemediationStep step, String coordinates, String detail);

    /** @param outcome how it went, in a few words, or {@code null} when there is nothing to add */
    void stepFinished(RemediationStep step, String coordinates, String outcome);

    /**
     * Called zero or more times between {@link #stepStarting} and {@link #stepFinished} for a step whose
     * duration cannot be predicted, so a live run does not go silent for minutes at a time.
     *
     * <p>Optional and additive: the empty default keeps every existing implementation, including
     * {@link #none()}, correct without any change. Only a step that genuinely needs it -- today, a full
     * local build -- ever calls it at all.
     *
     * @param detail extra context, or {@code null}; the same "safe to print" rule as {@link #stepStarting}
     */
    default void stepHeartbeat(RemediationStep step, String coordinates, String detail) {
        // Nothing to report to, by default.
    }

    /** A listener that says nothing. The default wherever progress is not being watched. */
    static RemediationProgressListener none() {
        return new RemediationProgressListener() {
            @Override
            public void stepStarting(RemediationStep step, String coordinates, String detail) {
                // Nothing to report to.
            }

            @Override
            public void stepFinished(RemediationStep step, String coordinates, String outcome) {
                // Nothing to report to.
            }
        };
    }
}
