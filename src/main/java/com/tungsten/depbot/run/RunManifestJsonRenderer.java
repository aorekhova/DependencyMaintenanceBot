package com.tungsten.depbot.run;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.util.Objects;

/** Renders a {@link RunManifest} as JSON with forced LF line endings, matching every other renderer here. */
public final class RunManifestJsonRenderer {

    private final ObjectWriter writer;

    public RunManifestJsonRenderer() {
        this.writer = JsonMapper.builder().build().writer(lfPrettyPrinter());
    }

    public String render(RunManifest manifest) {
        Objects.requireNonNull(manifest, "manifest");
        try {
            return writer.writeValueAsString(manifest) + "\n";
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not render the run manifest as JSON", e);
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
