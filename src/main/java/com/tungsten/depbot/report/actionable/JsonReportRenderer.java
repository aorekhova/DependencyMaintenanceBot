package com.tungsten.depbot.report.actionable;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.util.Objects;

/**
 * Renders the report as the JSON document written to disk.
 *
 * <p>This is the machine-readable half of the output and the contract downstream automation reads,
 * so the exact bytes matter. Two choices follow from that:
 *
 * <ul>
 *   <li><strong>Line endings are pinned to LF.</strong> Jackson's default pretty printer indents
 *       using {@code System.lineSeparator()}, which yields CRLF on Windows and LF on Linux — the
 *       same report would then produce different bytes on a developer machine than on a build
 *       agent, and every run would look like a change to anything comparing files or checksums.</li>
 *   <li><strong>Null fields are written explicitly.</strong> Jackson's default inclusion is kept
 *       rather than switched to non-null, so a consumer can tell "Mend did not supply this" from
 *       "this application forgot to emit it".</li>
 * </ul>
 *
 * <p>The report passed in is expected to have been through {@link ActionableReportRedactor} already;
 * this class does no masking of its own. It never sees or serialises the raw Mend response.
 */
public final class JsonReportRenderer {

    private final ObjectWriter writer;

    public JsonReportRenderer() {
        this.writer = JsonMapper.builder().build().writer(lfPrettyPrinter());
    }

    /**
     * @return the complete file content, ending in a newline as text files conventionally do
     */
    public String render(ActionableReport report) {
        Objects.requireNonNull(report, "report");
        try {
            return writer.writeValueAsString(report) + "\n";
        } catch (JsonProcessingException e) {
            // Message deliberately carries no report content: it may be large, and it may hold
            // vulnerability detail that does not belong in an error string.
            throw new IllegalStateException("Could not render the actionable report as JSON", e);
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
