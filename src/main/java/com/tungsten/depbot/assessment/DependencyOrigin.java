package com.tungsten.depbot.assessment;

import com.fasterxml.jackson.annotation.JsonCreator;

import java.util.Locale;

/**
 * Where the vulnerable dependency actually enters the build.
 *
 * <p>This is the question the jackson-databind pilot showed cannot be answered from Mend's data
 * alone, and it is what decides the shape of the fix: a directly declared version is edited in
 * place, a version property or an imported BOM is edited somewhere else entirely, and a transitive
 * arrival may need managing rather than upgrading.
 */
public enum DependencyOrigin {

    /** Declared as a {@code <dependency>} with its own {@code <version>}. */
    DIRECT,

    /** Pulled in by another dependency; nothing declares it. */
    TRANSITIVE,

    /** Declared, but the version comes from a {@code <properties>} entry. */
    PROPERTY,

    /** The version is pinned by this project's own {@code <dependencyManagement>}. */
    DEPENDENCY_MANAGEMENT,

    /** The version comes from an imported BOM, so the BOM's version is what has to move. */
    BOM,

    /** Not present on the examined refs at all, directly or transitively. */
    ABSENT,

    /** Present, but the assessment could not establish how it arrives. */
    UNKNOWN;

    /** Tolerant of case, whitespace, hyphens and spaces; an unrecognised value is rejected. */
    @JsonCreator
    public static DependencyOrigin from(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("origin is missing");
        }
        String normalized = raw.strip().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
        for (DependencyOrigin origin : values()) {
            if (origin.name().equals(normalized)) {
                return origin;
            }
        }
        throw new IllegalArgumentException("unrecognised dependency origin: " + raw.strip());
    }
}
