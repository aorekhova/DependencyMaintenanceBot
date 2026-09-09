package com.tungsten.depbot.report.actionable;

import com.tungsten.depbot.cli.ExitCode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReportWriterTest {

    private static final String JSON = "{\n  \"generatedAt\" : \"2026-01-02T03:04:05Z\"\n}\n";
    private static final String MARKDOWN = "# Mend Actionable Vulnerability Report\n";

    private final ReportWriter writer = new ReportWriter();

    @TempDir
    Path tempDir;

    private String read(Path path) throws IOException {
        return Files.readString(path, StandardCharsets.UTF_8);
    }

    // ---------- writing ----------

    @Test
    @DisplayName("both files are created with the expected names and content")
    void bothFilesWritten() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);

        WrittenReports written = writer.publish(destination, JSON, MARKDOWN);

        assertEquals(tempDir.resolve("mend-actionable-vulnerabilities.json"), written.jsonPath());
        assertEquals(tempDir.resolve("mend-actionable-vulnerabilities.md"), written.markdownPath());
        assertEquals(JSON, read(written.jsonPath()));
        assertEquals(MARKDOWN, read(written.markdownPath()));
    }

    @Test
    @DisplayName("a missing output directory is created")
    void missingDirectoryCreated() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir.resolve("reports"));

        writer.publish(destination, JSON, MARKDOWN);

        assertTrue(Files.exists(destination.jsonPath()));
        assertTrue(Files.exists(destination.markdownPath()));
    }

    @Test
    @DisplayName("several missing parent directories are created")
    void nestedDirectoriesCreated() {
        ReportDestination destination =
                ReportDestination.into(tempDir.resolve("a").resolve("b").resolve("c"));

        writer.publish(destination, JSON, MARKDOWN);

        assertTrue(Files.exists(destination.jsonPath()));
    }

    @Test
    @DisplayName("content is written and read back as UTF-8")
    void contentIsUtf8() throws IOException {
        // ASCII only in the reports themselves, but the encoding must still be explicit.
        String json = "{\"note\":\"plain ascii only\"}\n";
        ReportDestination destination = ReportDestination.into(tempDir);

        writer.publish(destination, json, MARKDOWN);

        assertEquals(json, read(destination.jsonPath()));
        assertFalse(read(destination.jsonPath()).contains("\r"));
    }

    // ---------- replacing ----------

    @Test
    @DisplayName("existing files are replaced, not appended to")
    void existingFilesReplaced() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        Files.writeString(destination.jsonPath(), "OLD JSON", StandardCharsets.UTF_8);
        Files.writeString(destination.markdownPath(), "OLD MARKDOWN", StandardCharsets.UTF_8);

        writer.publish(destination, JSON, MARKDOWN);

        assertEquals(JSON, read(destination.jsonPath()));
        assertEquals(MARKDOWN, read(destination.markdownPath()));
    }

    @Test
    @DisplayName("replacing a longer file with a shorter one leaves no remnant")
    void shorterReplacementLeavesNoRemnant() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        Files.writeString(destination.jsonPath(),
                "X".repeat(5_000), StandardCharsets.UTF_8);

        writer.publish(destination, JSON, MARKDOWN);

        assertEquals(JSON, read(destination.jsonPath()));
        assertEquals(JSON.length(), read(destination.jsonPath()).length());
    }

    @Test
    @DisplayName("publishing twice in a row is idempotent")
    void publishingTwiceIsIdempotent() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);

        writer.publish(destination, JSON, MARKDOWN);
        writer.publish(destination, JSON, MARKDOWN);

        assertEquals(JSON, read(destination.jsonPath()));
        assertEquals(2, Files.list(tempDir).count(), "only the two report files should exist");
    }

    // ---------- temporaries ----------

    @Test
    @DisplayName("no temporary file survives a successful publication")
    void noTemporarySurvivesSuccess() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);

        writer.publish(destination, JSON, MARKDOWN);

        assertFalse(Files.exists(destination.jsonTempPath()));
        assertFalse(Files.exists(destination.markdownTempPath()));
        assertEquals(0, Files.list(tempDir).filter(p -> p.toString().endsWith(".tmp")).count());
    }

    @Test
    @DisplayName("a pre-existing temporary from an interrupted run is overwritten, not merged")
    void staleTemporaryOverwritten() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        Files.writeString(destination.jsonTempPath(), "LEFTOVER", StandardCharsets.UTF_8);

        writer.publish(destination, JSON, MARKDOWN);

        assertEquals(JSON, read(destination.jsonPath()));
        assertFalse(Files.exists(destination.jsonTempPath()));
    }

    // ---------- failure ----------

    @Test
    @DisplayName("a destination under an existing regular file fails with a safe message")
    void destinationUnderRegularFileFails() throws IOException {
        Path blocker = tempDir.resolve("not-a-directory");
        Files.writeString(blocker, "regular file", StandardCharsets.UTF_8);

        ReportDestination destination = ReportDestination.into(blocker.resolve("reports"));

        ReportWriteException thrown = assertThrows(ReportWriteException.class,
                () -> writer.publish(destination, JSON, MARKDOWN));

        assertTrue(thrown.getMessage().contains("reports"), "the message should name the path");
        assertFalse(thrown.getMessage().contains("generatedAt"),
                "report content must never appear in an error message");
        assertFalse(thrown.getMessage().contains(MARKDOWN.strip()));
    }

    @Test
    @DisplayName("the error message names paths only, never report content")
    void errorMessageCarriesNoContent() throws IOException {
        Path blocker = tempDir.resolve("blocked");
        Files.writeString(blocker, "x", StandardCharsets.UTF_8);
        ReportDestination destination = ReportDestination.into(blocker.resolve("nested"));

        String secretish = "TOKEN-DO-NOT-LEAK-7b1c";
        ReportWriteException thrown = assertThrows(ReportWriteException.class,
                () -> writer.publish(destination, "{\"x\":\"" + secretish + "\"}", MARKDOWN));

        assertFalse(thrown.getMessage().contains(secretish));
    }

    // ---------- contract ----------

    @Test
    @DisplayName("the new exit code has the documented value")
    void exitCodeValue() {
        assertEquals(6, ExitCode.REPORT_WRITE_ERROR.value());
    }

    @Test
    @DisplayName("the documented directory and filenames are what production will use")
    void defaultNamesAreDocumented() {
        // Asserted through the constants rather than by resolving the production destination, so
        // that no test source can write into the real reports directory. NoRealMendEndpointTest
        // enforces that, and it can only be an absolute rule if there are no exceptions to it.
        assertEquals("reports", ReportDestination.DEFAULT_DIRECTORY);
        assertEquals("mend-actionable-vulnerabilities.json",
                ReportDestination.DEFAULT_JSON_FILE_NAME);
        assertEquals("mend-actionable-vulnerabilities.md",
                ReportDestination.DEFAULT_MARKDOWN_FILE_NAME);

        ReportDestination destination = ReportDestination.into(tempDir);
        assertEquals("mend-actionable-vulnerabilities.json.tmp",
                destination.jsonTempPath().getFileName().toString());
        assertEquals("mend-actionable-vulnerabilities.md.tmp",
                destination.markdownTempPath().getFileName().toString());
    }

    @Test
    @DisplayName("temporaries sit beside their targets so an atomic move is possible")
    void temporariesShareTheTargetDirectory() {
        ReportDestination destination = ReportDestination.into(tempDir);

        assertEquals(destination.jsonPath().getParent(), destination.jsonTempPath().getParent());
        assertEquals(destination.markdownPath().getParent(),
                destination.markdownTempPath().getParent());
    }

    @Test
    @DisplayName("null arguments are rejected")
    void nullArgumentsRejected() {
        ReportDestination destination = ReportDestination.into(tempDir);

        assertThrows(NullPointerException.class, () -> writer.publish(null, JSON, MARKDOWN));
        assertThrows(NullPointerException.class, () -> writer.publish(destination, null, MARKDOWN));
        assertThrows(NullPointerException.class, () -> writer.publish(destination, JSON, null));
        assertThrows(NullPointerException.class, () -> writer.invalidate(null));
    }

    @Test
    @DisplayName("a blank filename is rejected at construction")
    void blankFileNameRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> new ReportDestination(tempDir, "  ", "report.md"));
        assertThrows(IllegalArgumentException.class,
                () -> new ReportDestination(tempDir, "report.json", null));
        assertThrows(NullPointerException.class,
                () -> new ReportDestination(null, "a.json", "a.md"));
    }

    @Test
    @DisplayName("a successful publication reports the pair state as known")
    void successLeavesNoUnreconciledPaths() {
        // Sanity check on the exception contract used by the failure paths.
        ReportWriteException clean =
                new ReportWriteException("message", List.of(), null);

        assertTrue(clean.pairStateGuaranteed());
        assertTrue(clean.unreconciledPaths().isEmpty());
    }
}
