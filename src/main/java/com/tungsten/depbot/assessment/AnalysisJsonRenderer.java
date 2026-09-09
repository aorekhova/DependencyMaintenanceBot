package com.tungsten.depbot.assessment;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.util.Objects;

/**
 * Renders a validated {@link BatchAnalysis} as JSON, with forced LF line endings, matching the other
 * renderers.
 *
 * <p>What is written is this application's own validated model, not the text Claude produced -- the
 * saved {@code analysis.json} is guaranteed to be a document that satisfied validation, while Claude's
 * original wording is still preserved verbatim in the same attempt's {@code stdout.json}.
 */
public final class AnalysisJsonRenderer {

    private final ObjectWriter writer;

    public AnalysisJsonRenderer() {
        this.writer = JsonMapper.builder().build().writer(lfPrettyPrinter());
    }

    public String render(BatchAnalysis analysis) {
        Objects.requireNonNull(analysis, "analysis");
        return write(analysis, "batch analysis");
    }

    /** The invocation record, written alongside the analysis -- or on its own when there is none. */
    public String renderAttempt(BatchAnalysisAttempt attempt) {
        Objects.requireNonNull(attempt, "attempt");
        return write(attempt, "batch analysis attempt");
    }

    /** What survived both attempts when neither produced a coverage-complete analysis. */
    public String renderPartialAnalysisState(PartialAnalysisState partialAnalysisState) {
        Objects.requireNonNull(partialAnalysisState, "partialAnalysisState");
        return write(partialAnalysisState, "partial analysis state");
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
