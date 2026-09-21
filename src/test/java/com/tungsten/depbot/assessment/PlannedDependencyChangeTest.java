package com.tungsten.depbot.assessment;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fast regression tests for {@link PlannedDependencyChange}'s {@code EXCLUSION_ADDED} contract -- run
 * {@code 20260920-052841-210614}: Claude #1 set {@code dependencyCoordinates} to the HOST dependency
 * ({@code org.kordamp.json:json-lib-core}), named the coordinates actually being excluded
 * ({@code junit:junit}, {@code org.slf4j:jcl-over-slf4j}) only in the free-form narrative, and
 * {@link com.tungsten.depbot.implementation.PlanConformanceGate} -- which at the time treated
 * {@code dependencyCoordinates} as the excluded coordinate for every {@code EXCLUSION_ADDED} entry --
 * went looking for an exclusion of {@code org.kordamp.json:json-lib-core} that could never exist. The
 * contract is now unambiguous and structural: {@code dependencyCoordinates} is always the host, and
 * {@code excludedCoordinates} is always the (non-empty) list of what is actually excluded from it.
 */
class PlannedDependencyChangeTest {

    private static final String HOST = "org.kordamp.json:json-lib-core";

    @Test
    @DisplayName("an EXCLUSION_ADDED entry with a host and one or more excluded coordinates is accepted")
    void exclusionAddedWithHostAndExcludedCoordinatesIsAccepted() {
        PlannedDependencyChange change = new PlannedDependencyChange(
                HOST, null, null, "pom.xml", PlannedChangeType.EXCLUSION_ADDED,
                "excludes junit and jcl-over-slf4j from json-lib-core",
                List.of("junit:junit", "org.slf4j:jcl-over-slf4j"));

        assertEquals(HOST, change.dependencyCoordinates());
        assertEquals(List.of("junit:junit", "org.slf4j:jcl-over-slf4j"), change.excludedCoordinates());
    }

    @Test
    @DisplayName("an EXCLUSION_ADDED entry with no excludedCoordinates at all is rejected -- the excluded "
            + "coordinate(s) must never live only in prose")
    void exclusionAddedWithNoExcludedCoordinatesIsRejected() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                new PlannedDependencyChange(HOST, null, null, "pom.xml", PlannedChangeType.EXCLUSION_ADDED,
                        "excludes junit and jcl-over-slf4j from json-lib-core", null));

        assertTrue(exception.getMessage().contains("excludedCoordinates"), exception.getMessage());
    }

    @Test
    @DisplayName("an EXCLUSION_ADDED entry with an empty excludedCoordinates list is rejected")
    void exclusionAddedWithEmptyExcludedCoordinatesIsRejected() {
        assertThrows(IllegalArgumentException.class, () ->
                new PlannedDependencyChange(HOST, null, null, "pom.xml", PlannedChangeType.EXCLUSION_ADDED,
                        "excludes junit and jcl-over-slf4j from json-lib-core", List.of()));
    }

    @Test
    @DisplayName("an EXCLUSION_ADDED entry with a blank entry in excludedCoordinates is rejected")
    void exclusionAddedWithBlankExcludedCoordinateEntryIsRejected() {
        assertThrows(IllegalArgumentException.class, () ->
                new PlannedDependencyChange(HOST, null, null, "pom.xml", PlannedChangeType.EXCLUSION_ADDED,
                        "excludes junit from json-lib-core", java.util.Arrays.asList("junit:junit", " ")));
    }

    @Test
    @DisplayName("a non-EXCLUSION_ADDED entry with excludedCoordinates set is rejected -- the field is only "
            + "meaningful for EXCLUSION_ADDED")
    void nonExclusionEntryWithExcludedCoordinatesIsRejected() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                new PlannedDependencyChange("com.example:artifact", "1.0", "1.1", "pom.xml",
                        PlannedChangeType.VERSION_BUMP, "raise the version", List.of("com.example:other")));

        assertTrue(exception.getMessage().contains("excludedCoordinates"), exception.getMessage());
    }

    @Test
    @DisplayName("the legacy 6-arg constructor still works for every non-EXCLUSION_ADDED changeType")
    void legacyConstructorStillWorksForNonExclusionTypes() {
        PlannedDependencyChange change = new PlannedDependencyChange(
                "com.example:artifact", "1.0", "1.1", "pom.xml", PlannedChangeType.VERSION_BUMP,
                "raise the version");

        assertEquals(List.of(), change.excludedCoordinates());
    }

    @Test
    @DisplayName("the legacy 6-arg constructor fails closed for EXCLUSION_ADDED, since it can never supply "
            + "excludedCoordinates -- forcing every EXCLUSION_ADDED call site onto the explicit contract")
    void legacyConstructorFailsClosedForExclusionAdded() {
        assertThrows(IllegalArgumentException.class, () ->
                new PlannedDependencyChange(HOST, null, null, "pom.xml", PlannedChangeType.EXCLUSION_ADDED,
                        "excludes junit from json-lib-core"));
    }
}
