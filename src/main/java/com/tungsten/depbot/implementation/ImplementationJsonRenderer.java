package com.tungsten.depbot.implementation;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.validation.ValidationOutcome;

import java.util.Objects;

/**
 * Renders the implementation phase's two documents as JSON, with forced LF line endings, matching the
 * other renderers.
 *
 * <p>What is written is this application's own validated model rather than the text Claude produced, so
 * a saved report is guaranteed to be one that satisfied validation. Claude's original wording is still
 * preserved verbatim in the same attempt's {@code stdout.json}.
 */
public final class ImplementationJsonRenderer {

    private final ObjectWriter writer;

    public ImplementationJsonRenderer() {
        this.writer = JsonMapper.builder().build().writer(lfPrettyPrinter());
    }

    public String render(ImplementationReport report) {
        Objects.requireNonNull(report, "report");
        return write(report, "implementation report");
    }

    public String renderAttempt(ImplementationAttempt attempt) {
        Objects.requireNonNull(attempt, "attempt");
        return write(attempt, "implementation attempt");
    }

    /**
     * The local gate's verdict on its own, next to the Maven output it came from.
     *
     * <p>Written separately from the attempt record rather than only inside it, because the one question an
     * operator asks about a refused remediation is "what did validation say", and it should be answerable
     * by opening one small file.
     */
    public String renderValidation(ValidationOutcome validation) {
        Objects.requireNonNull(validation, "validation");
        return write(validation, "validation outcome");
    }

    /** The plan-conformance gate's own verdict, next to the implementation attempt it belongs to. */
    public String renderPlanConformance(PlanConformanceResult planConformance) {
        Objects.requireNonNull(planConformance, "planConformance");
        return write(planConformance, "plan conformance result");
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
