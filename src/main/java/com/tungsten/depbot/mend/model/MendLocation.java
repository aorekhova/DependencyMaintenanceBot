package com.tungsten.depbot.mend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A place where Mend detected the affected library.
 *
 * <p>{@code path} is what tells a developer where to look; {@code matchType} describes how
 * confidently Mend identified it. Both are optional, and a path is never invented.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MendLocation(
        String matchType,
        String path) {
}
