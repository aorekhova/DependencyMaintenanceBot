package com.tungsten.depbot.mend.history;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.util.Objects;

/** Renders a {@link MendHistoryIndex} as JSON with forced LF line endings, matching every other renderer here. */
public final class MendHistoryIndexJsonRenderer {

    private final ObjectWriter writer;

    public MendHistoryIndexJsonRenderer() {
        this.writer = JsonMapper.builder().build().writer(lfPrettyPrinter());
    }

    public String render(MendHistoryIndex index) {
        Objects.requireNonNull(index, "index");
        try {
            return writer.writeValueAsString(index) + "\n";
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not render the Mend history index as JSON", e);
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
