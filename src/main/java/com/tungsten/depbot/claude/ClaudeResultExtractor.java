package com.tungsten.depbot.claude;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Reads the {@code result} text out of a Claude Code {@code --output-format json} document.
 *
 * <p>Only the three fields this application acts on are looked at -- {@code result},
 * {@code is_error} and {@code subtype}. Everything else Claude Code reports (token usage, cost,
 * timings, session id, per-model breakdowns) is left in the saved {@code stdout.json} for a human to
 * read and is deliberately not modelled: binding it would make this application break every time
 * the CLI adds a field.
 */
public final class ClaudeResultExtractor {

    private final JsonMapper mapper = JsonMapper.builder().build();

    /** Reads the document Claude wrote for one invocation. */
    public ClaudeResult extractFrom(Path stdoutFile) {
        Objects.requireNonNull(stdoutFile, "stdoutFile");
        if (!Files.exists(stdoutFile)) {
            throw new ClaudeOutputException(
                    "Claude Code produced no output document at " + stdoutFile + ".");
        }
        String content;
        try {
            content = Files.readString(stdoutFile, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new ClaudeOutputException("Could not read " + stdoutFile, e);
        }
        return extract(content);
    }

    /**
     * @throws ClaudeOutputException if the text is not a JSON object, or carries no {@code result}
     *                               field -- both mean there is no answer to act on, which is a
     *                               different situation from an answer this application dislikes
     */
    public ClaudeResult extract(String stdoutJson) {
        if (stdoutJson == null || stdoutJson.isBlank()) {
            throw new ClaudeOutputException("Claude Code produced an empty output document.");
        }

        JsonNode root;
        try {
            root = mapper.readTree(stdoutJson);
        } catch (JsonProcessingException e) {
            // The parser's own message is safe: Jackson reports a position and a token kind, not the
            // surrounding content. The document itself is never included.
            throw new ClaudeOutputException(
                    "Claude Code's output was not valid JSON (" + e.getOriginalMessage() + ").");
        }

        if (root == null || !root.isObject()) {
            throw new ClaudeOutputException(
                    "Claude Code's output was valid JSON but not an object, so it carries no result.");
        }

        JsonNode result = root.get("result");
        if (result == null || result.isNull() || !result.isTextual()) {
            throw new ClaudeOutputException(
                    "Claude Code's output has no textual \"result\" field, so there is no answer to read.");
        }

        JsonNode isError = root.get("is_error");
        JsonNode subtype = root.get("subtype");

        return new ClaudeResult(
                isError != null && isError.asBoolean(false),
                subtype != null && subtype.isTextual() ? subtype.asText() : null,
                result.asText());
    }

    /**
     * Best-effort look at just the {@code subtype} field, tolerant of a document that is not a usable
     * result at all -- which is exactly the shape Claude Code can write for an abnormal termination
     * such as {@code error_max_turns}, where the process also exits non-zero and the strict
     * {@link #extractFrom(Path)} would refuse the whole document for having no textual {@code result}.
     * Never throws: a missing file, unreadable content, or a document with no subtype all simply mean
     * there is nothing more specific to add to a failure description than the generic one already has.
     */
    public String readSubtypeIfPresent(Path stdoutFile) {
        return readFieldIfPresent(stdoutFile, "subtype");
    }

    /**
     * Best-effort look at just the {@code session_id} field, tolerant in exactly the same way as
     * {@link #readSubtypeIfPresent(Path)} -- an abnormal termination such as {@code error_max_turns}
     * still carries the session id in the document Claude Code wrote, even though {@code result} is not
     * usable. This is what lets a short, tool-free finalization call resume the same session with
     * {@code --resume} instead of starting over with no memory of what was already investigated.
     */
    public String readSessionIdIfPresent(Path stdoutFile) {
        return readFieldIfPresent(stdoutFile, "session_id");
    }

    private String readFieldIfPresent(Path stdoutFile, String fieldName) {
        if (stdoutFile == null || !Files.exists(stdoutFile)) {
            return null;
        }
        try {
            JsonNode root = mapper.readTree(Files.readString(stdoutFile, StandardCharsets.UTF_8));
            if (root == null || !root.isObject()) {
                return null;
            }
            JsonNode field = root.get(fieldName);
            return field != null && field.isTextual() ? field.asText() : null;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }
}
