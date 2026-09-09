package com.tungsten.depbot.remediation;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Reads a persisted {@code group-state.json} back into a {@link GroupState} -- the read-side counterpart
 * of {@link GroupStateJsonRenderer}, needed only so {@link GroupStateWriter#markFinalOutcome} can patch in
 * a fact learned after the group's own attempt already finished (a later, cohort-level integration
 * failure) without losing everything already recorded for it.
 *
 * <p>Unknown properties are ignored rather than rejected, so a {@code group-state.json} written by an
 * older version of this bot -- one that still carried {@code initialPlanningCycle}/{@code
 * repairPlanningCycle} from the since-removed Planner/Plan Reviewer cycle -- can still be read back
 * instead of failing outright.
 */
public final class GroupStateJsonReader {

    private final JsonMapper mapper = JsonMapper.builder()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    public GroupState read(Path path) {
        Objects.requireNonNull(path, "path");
        try {
            return mapper.readValue(Files.readString(path, StandardCharsets.UTF_8), GroupState.class);
        } catch (IOException e) {
            throw new IllegalStateException("Could not read " + path + ": " + e.getMessage(), e);
        }
    }
}
