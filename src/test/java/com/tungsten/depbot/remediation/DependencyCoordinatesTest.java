package com.tungsten.depbot.remediation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DependencyCoordinatesTest {

    @Test
    @DisplayName("a well-formed groupId:artifactId pair parses into its two parts")
    void parsesWellFormedCoordinates() {
        DependencyCoordinates parsed = DependencyCoordinates.parse("com.fasterxml.jackson.core:jackson-databind");

        assertEquals("com.fasterxml.jackson.core", parsed.groupId());
        assertEquals("jackson-databind", parsed.artifactId());
        assertEquals("com.fasterxml.jackson.core:jackson-databind", parsed.coordinates());
    }

    @Test
    @DisplayName("surrounding whitespace is stripped from the raw value and from each side")
    void stripsWhitespace() {
        DependencyCoordinates parsed = DependencyCoordinates.parse("  g : a  ");

        assertEquals("g", parsed.groupId());
        assertEquals("a", parsed.artifactId());
    }

    @Test
    @DisplayName("a null value is rejected")
    void nullValueIsRejected() {
        assertThrows(InvalidDependencyFilterException.class, () -> DependencyCoordinates.parse(null));
    }

    @Test
    @DisplayName("a blank value is rejected")
    void blankValueIsRejected() {
        assertThrows(InvalidDependencyFilterException.class, () -> DependencyCoordinates.parse("   "));
    }

    @Test
    @DisplayName("a value with no colon at all is rejected")
    void noColonIsRejected() {
        assertThrows(InvalidDependencyFilterException.class, () -> DependencyCoordinates.parse("jackson-databind"));
    }

    @Test
    @DisplayName("a value with more than one colon is rejected")
    void multipleColonsAreRejected() {
        assertThrows(InvalidDependencyFilterException.class,
                () -> DependencyCoordinates.parse("com.fasterxml.jackson.core:jackson-databind:2.22.0"));
    }

    @Test
    @DisplayName("a blank groupId is rejected")
    void blankGroupIdIsRejected() {
        assertThrows(InvalidDependencyFilterException.class, () -> DependencyCoordinates.parse(":jackson-databind"));
    }

    @Test
    @DisplayName("a blank artifactId is rejected")
    void blankArtifactIdIsRejected() {
        assertThrows(InvalidDependencyFilterException.class,
                () -> DependencyCoordinates.parse("com.fasterxml.jackson.core:"));
    }

    @Test
    @DisplayName("the error message names the offending raw value, safe to print to the console")
    void errorMessageNamesTheRawValue() {
        InvalidDependencyFilterException e = assertThrows(InvalidDependencyFilterException.class,
                () -> DependencyCoordinates.parse("nope"));

        assertTrue(e.getMessage().contains("nope"), e.getMessage());
    }
}
