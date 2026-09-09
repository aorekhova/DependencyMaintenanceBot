package com.tungsten.depbot.mend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The library a Mend vulnerability was found in.
 *
 * <p>Every component is optional as far as this application is concerned: Mend may omit any of
 * them, in which case the field is {@code null}. Nothing here is ever inferred or filled in — in
 * particular Maven coordinates are only assembled later, and only when groupId, artifactId and
 * version are all genuinely present.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MendLibrary(
        String keyUuid,
        String filename,
        String type,
        String description,
        String sha1,
        String name,
        String artifactId,
        String version,
        String groupId,
        String architecture,
        String languageVersion) {
}
