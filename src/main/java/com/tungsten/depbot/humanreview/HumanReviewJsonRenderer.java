package com.tungsten.depbot.humanreview;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.util.Objects;

/** Renders a {@link HumanReviewReport}/{@link HumanReviewAttempt} as JSON, with forced LF line endings. */
public final class HumanReviewJsonRenderer {

    private final ObjectWriter writer;

    public HumanReviewJsonRenderer() {
        this.writer = JsonMapper.builder().build().writer(lfPrettyPrinter());
    }

    public String render(HumanReviewReport report) {
        Objects.requireNonNull(report, "report");
        return write(report, "human review report");
    }

    public String renderAttempt(HumanReviewAttempt attempt) {
        Objects.requireNonNull(attempt, "attempt");
        return write(attempt, "human review attempt");
    }

    private String write(Object document, String description) {
        try {
            return writer.writeValueAsString(document) + "\n";
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not render the " + description + " as JSON", e);
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
