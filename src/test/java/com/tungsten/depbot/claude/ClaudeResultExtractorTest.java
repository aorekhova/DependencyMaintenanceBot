package com.tungsten.depbot.claude;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClaudeResultExtractorTest {

    @TempDir
    Path tempDir;

    private final ClaudeResultExtractor extractor = new ClaudeResultExtractor();

    @Test
    @DisplayName("the result text is lifted out of the CLI's JSON document")
    void resultTextIsExtracted() {
        ClaudeResult result = extractor.extract(
                "{\"is_error\":false,\"subtype\":\"success\",\"result\":\"the answer\"}");

        assertFalse(result.isError());
        assertEquals("success", result.subtype());
        assertEquals("the answer", result.text());
        assertTrue(result.usable());
    }

    @Test
    @DisplayName("every other field the CLI reports is ignored rather than bound")
    void unmodelledFieldsAreIgnored() {
        String document = """
                {"is_error":false,"duration_api_ms":49884,"num_turns":10,"session_id":"abc",
                 "total_cost_usd":0.35,"usage":{"input_tokens":44,"cache":{"nested":{"deep":1}}},
                 "permission_denials":[],"result":"done","type":"result"}
                """;

        assertEquals("done", extractor.extract(document).text());
    }

    @Test
    @DisplayName("is_error is honoured even when the process exited zero")
    void isErrorIsHonoured() {
        ClaudeResult result = extractor.extract("{\"is_error\":true,\"result\":\"hit the turn limit\"}");

        assertTrue(result.isError());
        assertFalse(result.usable(), "an errored run must not be treated as a usable answer");
    }

    @Test
    @DisplayName("a result containing braces and quotes survives extraction unchanged")
    void embeddedJsonInTheResultSurvives() {
        ClaudeResult result = extractor.extract(
                "{\"result\":\"here it is: {\\\"conclusion\\\": \\\"NO_ACTION_REQUIRED\\\"}\"}");

        assertEquals("here it is: {\"conclusion\": \"NO_ACTION_REQUIRED\"}", result.text());
    }

    @Test
    @DisplayName("an empty result is read but is not usable")
    void emptyResultIsNotUsable() {
        assertFalse(extractor.extract("{\"result\":\"\"}").usable());
    }

    @Test
    @DisplayName("output that is not JSON at all is rejected, without echoing it")
    void nonJsonOutputIsRejected() {
        String proxyLoginPage = "<html><body>Please sign in</body></html>";

        ClaudeOutputException thrown =
                assertThrows(ClaudeOutputException.class, () -> extractor.extract(proxyLoginPage));

        assertFalse(thrown.getMessage().contains("Please sign in"),
                "the output itself must never be quoted back: " + thrown.getMessage());
    }

    @Test
    @DisplayName("valid JSON that is not an object is rejected")
    void nonObjectJsonIsRejected() {
        assertThrows(ClaudeOutputException.class, () -> extractor.extract("[1, 2, 3]"));
    }

    @Test
    @DisplayName("a document with no textual result field is rejected")
    void missingResultFieldIsRejected() {
        assertThrows(ClaudeOutputException.class, () -> extractor.extract("{\"is_error\":false}"));
        assertThrows(ClaudeOutputException.class, () -> extractor.extract("{\"result\":null}"));
        assertThrows(ClaudeOutputException.class, () -> extractor.extract("{\"result\":42}"));
    }

    @Test
    @DisplayName("empty or absent output is rejected")
    void emptyOrAbsentOutputIsRejected() {
        assertThrows(ClaudeOutputException.class, () -> extractor.extract(""));
        assertThrows(ClaudeOutputException.class, () -> extractor.extract(null));
        assertThrows(ClaudeOutputException.class,
                () -> extractor.extractFrom(tempDir.resolve("never-written.json")));
    }

    @Test
    @DisplayName("the document is read from the attempt directory the invoker wrote it to")
    void documentIsReadFromDisk() throws IOException {
        Path stdout = tempDir.resolve(ClaudeArtifacts.STDOUT_FILE);
        Files.writeString(stdout, "{\"result\":\"from disk\"}", StandardCharsets.UTF_8);

        assertEquals("from disk", extractor.extractFrom(stdout).text());
    }

    // ---- lenient reads used only to decide whether a finalization attempt is possible --------------

    @Test
    @DisplayName("the session id is read leniently, even from a document with no usable result")
    void sessionIdIsReadEvenWithoutAUsableResult() throws IOException {
        Path stdout = tempDir.resolve(ClaudeArtifacts.STDOUT_FILE);
        Files.writeString(stdout,
                "{\"is_error\":true,\"subtype\":\"error_max_turns\",\"session_id\":\"sess-abc\"}",
                StandardCharsets.UTF_8);

        assertEquals("sess-abc", extractor.readSessionIdIfPresent(stdout));
        assertEquals("error_max_turns", extractor.readSubtypeIfPresent(stdout));
    }

    @Test
    @DisplayName("a missing session id, a missing file, or unreadable content all read as absent, never throw")
    void sessionIdIsAbsentRatherThanThrowing() throws IOException {
        assertNull(extractor.readSessionIdIfPresent(null));
        assertNull(extractor.readSessionIdIfPresent(tempDir.resolve("never-written.json")));

        Path noSessionId = tempDir.resolve("no-session-id.json");
        Files.writeString(noSessionId, "{\"result\":\"done\"}", StandardCharsets.UTF_8);
        assertNull(extractor.readSessionIdIfPresent(noSessionId));

        Path notJson = tempDir.resolve("not-json.json");
        Files.writeString(notJson, "not json at all", StandardCharsets.UTF_8);
        assertNull(extractor.readSessionIdIfPresent(notJson));
    }
}
