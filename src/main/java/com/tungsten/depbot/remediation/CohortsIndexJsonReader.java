package com.tungsten.depbot.remediation;

import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Reads a persisted {@code cohorts.json} back into a {@link CohortsIndex} -- the read-side counterpart
 * of {@link CohortsIndexJsonRenderer}, needed so a standalone {@code publish} command can act on a run
 * {@code remediate} already finished, without re-running any part of it.
 */
public final class CohortsIndexJsonReader {

    /** The file name {@code VulnerabilityRemediationService} writes this index under, in every run directory. */
    public static final String FILE_NAME = "cohorts.json";

    private final JsonMapper mapper = JsonMapper.builder().build();

    public CohortsIndex read(Path path) {
        Objects.requireNonNull(path, "path");
        try {
            return mapper.readValue(Files.readString(path, StandardCharsets.UTF_8), CohortsIndex.class);
        } catch (IOException e) {
            throw new PublicationSourceException("Could not read " + path + ": " + e.getMessage(), e);
        }
    }
}
