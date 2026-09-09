package com.tungsten.depbot.remediation;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.git.RepositoryRefreshOutcome;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Reads a persisted {@code repository-refresh.json} back into a {@link RepositoryRefreshOutcome} -- the
 * read-side counterpart of {@link RepositoryRefreshOutcomeJsonRenderer}, needed so {@code remediate} can
 * report the verified source ref/SHA the run actually synchronized to, without threading a new return
 * value through {@code VulnerabilityRemediationService} for a fact this file already records.
 */
public final class RepositoryRefreshOutcomeJsonReader {

    /** The file name {@code VulnerabilityRemediationService} writes this outcome under, in every run directory. */
    public static final String FILE_NAME = "repository-refresh.json";

    private final JsonMapper mapper = JsonMapper.builder().build();

    public RepositoryRefreshOutcome read(Path path) {
        Objects.requireNonNull(path, "path");
        try {
            return mapper.readValue(Files.readString(path, StandardCharsets.UTF_8), RepositoryRefreshOutcome.class);
        } catch (IOException e) {
            throw new PublicationSourceException("Could not read " + path + ": " + e.getMessage(), e);
        }
    }
}
