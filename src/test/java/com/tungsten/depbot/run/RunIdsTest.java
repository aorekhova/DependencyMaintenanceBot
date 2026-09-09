package com.tungsten.depbot.run;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RunIdsTest {

    @Test
    @DisplayName("a run id is a UTC timestamp with a short suffix")
    void idIsATimestampWithASuffix() {
        Clock fixed = Clock.fixed(Instant.parse("2026-08-10T14:05:06Z"), ZoneOffset.UTC);

        assertTrue(RunIds.generate(fixed).startsWith("20260810-140506-"), RunIds.generate(fixed));
    }

    @Test
    @DisplayName("a run id contains only characters git accepts in a branch name")
    void idIsSafeInABranchName() {
        for (int attempt = 0; attempt < 200; attempt++) {
            String runId = RunIds.generate();
            assertTrue(runId.matches("[0-9a-f-]+"),
                    "a run id becomes part of a branch name, so it must not need escaping: " + runId);
        }
    }

    @Test
    @DisplayName("two ids generated in the same second still differ")
    void idsInTheSameSecondDiffer() {
        Clock fixed = Clock.fixed(Instant.parse("2026-08-10T14:05:06Z"), ZoneOffset.UTC);
        Set<String> ids = new HashSet<>();

        for (int attempt = 0; attempt < 50; attempt++) {
            ids.add(RunIds.generate(fixed));
        }

        assertTrue(ids.size() > 1, "the random suffix is what keeps concurrent runs from colliding");
        assertEquals(1, ids.stream().map(id -> id.substring(0, 15)).distinct().count());
    }
}
