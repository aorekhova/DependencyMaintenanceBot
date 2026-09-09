package com.tungsten.depbot.remediation;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.git.RepositoryRefreshOutcome;

import java.util.Objects;

/** Renders a {@link RepositoryRefreshOutcome} as JSON, with forced LF line endings, matching the other renderers. */
public final class RepositoryRefreshOutcomeJsonRenderer {

    private final ObjectWriter writer;

    public RepositoryRefreshOutcomeJsonRenderer() {
        this.writer = JsonMapper.builder().build().writer(lfPrettyPrinter());
    }

    public String render(RepositoryRefreshOutcome outcome) {
        Objects.requireNonNull(outcome, "outcome");
        try {
            return writer.writeValueAsString(outcome) + "\n";
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not render the repository refresh outcome as JSON", e);
        }
    }

    private static DefaultPrettyPrinter lfPrettyPrinter() {
        DefaultIndenter lfIndenter = new DefaultIndenter("  ", "\n");
        DefaultPrettyPrinter printer = new DefaultPrettyPrinter();
        printer.indentObjectsWith(lfIndenter);
        printer.indentArraysWith(lfIndenter);
        return printer;
    }
}
