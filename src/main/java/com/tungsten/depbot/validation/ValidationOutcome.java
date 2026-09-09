package com.tungsten.depbot.validation;

import java.util.List;
import java.util.Objects;

/**
 * What the local gate found, with the exact command it ran so the verdict is reproducible by hand.
 *
 * <p>{@code output} is Maven's combined output, capped. It is carried out rather than written here for the
 * same reason the diff is: where an artifact belongs is the phase service's business. It is kept on every
 * path, because the output of a failed resolution is the first thing anyone will want to read.
 *
 * <p>{@code resolvedVersion} is the one version the gate actually found the coordinate resolving to after
 * the change -- a structured fact, not something read back out of {@code reason}'s prose. It is
 * deliberately {@code null} whenever there is no single, unambiguous answer: no vulnerable version was
 * being checked, the coordinate no longer resolves at all, or more than one version resolves across a
 * multi-module tree. A caller that wants "the version this change actually landed on" (for a commit
 * message, say) must treat {@code null} as "not reliably known," never invent a value to fill the gap.
 */
public record ValidationOutcome(
        ValidationStatus status,
        String reason,
        List<String> command,
        String output,
        String resolvedVersion) {

    public ValidationOutcome {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(reason, "reason");
        command = command == null ? List.of() : List.copyOf(command);
        output = output == null ? "" : output;
    }

    public static ValidationOutcome passed(String reason, List<String> command, String output) {
        return passed(reason, command, output, null);
    }

    /** As {@link #passed(String, List, String)}, additionally recording the version actually resolved. */
    public static ValidationOutcome passed(
            String reason, List<String> command, String output, String resolvedVersion) {
        return new ValidationOutcome(ValidationStatus.PASSED, reason, command, output, resolvedVersion);
    }

    public static ValidationOutcome failed(String reason, List<String> command, String output) {
        return new ValidationOutcome(ValidationStatus.FAILED, reason, command, output, null);
    }

    public static ValidationOutcome notRun(String reason, List<String> command, String output) {
        return new ValidationOutcome(ValidationStatus.NOT_RUN, reason, command, output, null);
    }

    public boolean permitsCommit() {
        return status.permitsCommit();
    }
}
