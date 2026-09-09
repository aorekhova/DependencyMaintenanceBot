package com.tungsten.depbot.mend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A remediation Mend recommends for a vulnerability.
 *
 * <p>Appears both as the single {@code topFix} and as entries in {@code allFixes}. Every component
 * is optional; a fix carrying only a {@code type} is still a valid fix and must be preserved
 * rather than discarded.
 *
 * <p>{@code fixResolution} is the field a developer acts on — typically the upgraded coordinates.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MendFix(
        String vulnerability,
        String type,
        String origin,
        String url,
        String fixResolution,
        String date,
        String message) {
}
