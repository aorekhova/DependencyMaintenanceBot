package com.tungsten.depbot.remediation;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * What {@link RemediationGroupValidator} produced: the remediation groups from a
 * {@code BatchAnalysis} that are safe to route onward, and why any group Claude proposed was not.
 *
 * <p>{@code invalidGroupReasons} covers exactly one situation: {@code RemediationGroupValidator} found
 * that a proposed group's structure could not be trusted against the batch's real findings (most often,
 * a member coordinate that does not correspond to any finding actually in this run). Every finding
 * belonging to such a group fails closed the same way an unparseable analysis would.
 */
public record GroupingValidationOutcome(
        List<ValidatedRemediationGroup> validGroups, Map<String, String> invalidGroupReasons) {

    public GroupingValidationOutcome {
        Objects.requireNonNull(validGroups, "validGroups");
        Objects.requireNonNull(invalidGroupReasons, "invalidGroupReasons");
        validGroups = List.copyOf(validGroups);
        invalidGroupReasons = Map.copyOf(invalidGroupReasons);
    }
}
