package com.tungsten.depbot.remediation;

import java.util.Objects;

/**
 * Exact {@code groupId:artifactId} coordinates identifying one library for a
 * {@code remediate --dependency} pilot run.
 */
public record DependencyCoordinates(String groupId, String artifactId) {

    public DependencyCoordinates {
        Objects.requireNonNull(groupId, "groupId");
        Objects.requireNonNull(artifactId, "artifactId");
    }

    public String coordinates() {
        return groupId + ":" + artifactId;
    }

    /**
     * Parses {@code raw} as exactly one colon-separated {@code groupId:artifactId} pair.
     *
     * @throws InvalidDependencyFilterException if {@code raw} is null or blank, has no colon, has
     *                                           more than one colon, or either side is blank
     */
    public static DependencyCoordinates parse(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new InvalidDependencyFilterException(
                    "a value is required, in the form groupId:artifactId "
                            + "(for example com.fasterxml.jackson.core:jackson-databind).");
        }

        String trimmed = raw.strip();
        int firstColon = trimmed.indexOf(':');
        int lastColon = trimmed.lastIndexOf(':');
        if (firstColon <= 0 || firstColon != lastColon || firstColon == trimmed.length() - 1) {
            throw new InvalidDependencyFilterException(
                    "expected exactly one colon, in the form groupId:artifactId, but got \""
                            + trimmed + "\".");
        }

        String groupId = trimmed.substring(0, firstColon).strip();
        String artifactId = trimmed.substring(firstColon + 1).strip();
        if (groupId.isBlank() || artifactId.isBlank()) {
            throw new InvalidDependencyFilterException(
                    "both groupId and artifactId must be non-blank, but got \"" + trimmed + "\".");
        }

        return new DependencyCoordinates(groupId, artifactId);
    }
}
