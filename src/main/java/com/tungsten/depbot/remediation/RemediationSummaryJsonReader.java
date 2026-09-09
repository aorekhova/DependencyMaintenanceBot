package com.tungsten.depbot.remediation;

import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Reads a persisted {@code remediation-summary.json} back into a {@link RemediationSummary} -- the
 * read-side counterpart of {@link RemediationSummaryJsonRenderer}, needed so a standalone {@code publish}
 * command can find every Human Review group without re-running any part of {@code remediate}.
 */
public final class RemediationSummaryJsonReader {

    private final JsonMapper mapper = JsonMapper.builder().build();

    public RemediationSummary read(Path path) {
        Objects.requireNonNull(path, "path");
        try {
            return mapper.readValue(Files.readString(path, StandardCharsets.UTF_8), RemediationSummary.class);
        } catch (IOException e) {
            throw new PublicationSourceException("Could not read " + path + ": " + e.getMessage(), e);
        }
    }
}
