package com.tungsten.depbot.remediation;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.util.Objects;

/**
 * Renders a {@link RemediationPlan} as JSON with forced LF line endings.
 *
 * <p>Jackson's default pretty printer uses {@code System.lineSeparator()}, which is CRLF on
 * Windows; that would make the file's bytes depend on the OS it was generated on. The custom
 * indenter below forces {@code "\n"} regardless of platform, matching {@code JsonReportRenderer}.
 */
public final class RemediationPlanJsonRenderer {

    private final ObjectWriter writer;

    public RemediationPlanJsonRenderer() {
        this.writer = JsonMapper.builder().build().writer(lfPrettyPrinter());
    }

    public String render(RemediationPlan plan) {
        Objects.requireNonNull(plan, "plan");
        try {
            return writer.writeValueAsString(plan) + "\n";
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not render the remediation plan as JSON", e);
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
