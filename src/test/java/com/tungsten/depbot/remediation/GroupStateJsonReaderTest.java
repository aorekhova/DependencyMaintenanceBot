package com.tungsten.depbot.remediation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link GroupStateJsonReader} must keep reading a {@code group-state.json} written by an older version
 * of this bot -- one from before the Planner/Plan Reviewer cycle was removed, which still carried
 * {@code initialPlanningCycle}/{@code repairPlanningCycle} keys this schema no longer has -- rather than
 * failing outright. Nothing in this codebase reads a group's own persisted state back to skip
 * already-done work, so the only real requirement is that an old file does not crash a later read.
 */
class GroupStateJsonReaderTest {

    private final GroupStateJsonReader reader = new GroupStateJsonReader();

    @Test
    @DisplayName("a group-state.json carrying legacy initialPlanningCycle/repairPlanningCycle keys is "
            + "still read back instead of failing")
    void legacyPlanningCycleKeysAreIgnoredNotRejected(@TempDir Path tempDir) throws IOException {
        String legacyJson = """
                {
                  "schemaVersion" : "1.0",
                  "runId" : "run1",
                  "groupId" : "g-a",
                  "memberCoordinates" : [ "com.example:artifact-a" ],
                  "verifiedSourceRef" : "refs/remotes/origin/release/9.2",
                  "verifiedSourceSha" : "abc123",
                  "risky" : false,
                  "automationSafety" : "AUTOMATIC_ALLOWED",
                  "automationSafetyReason" : "no coordinated or runtime-sensitive dependency is involved",
                  "lastCompletedStage" : "FINAL_OUTCOME_DECIDED",
                  "updatedAt" : "2026-01-01T00:00:00Z",
                  "implementationAttempts" : [ ],
                  "applicablePatch" : null,
                  "finalOutcome" : null,
                  "publicationOutcome" : null,
                  "initialPlanningCycle" : {
                    "planningAttempts" : [ ],
                    "reviewAttempts" : [ ]
                  },
                  "repairPlanningCycle" : null
                }
                """;
        Path path = tempDir.resolve("group-state.json");
        Files.writeString(path, legacyJson, StandardCharsets.UTF_8);

        GroupState state = reader.read(path);

        assertEquals("run1", state.runId());
        assertEquals("g-a", state.groupId());
        assertEquals(GroupLifecycleStage.FINAL_OUTCOME_DECIDED, state.lastCompletedStage());
        assertTrue(state.implementationAttempts().isEmpty());
    }
}
