package com.tungsten.depbot.report.actionable;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers the stale-report guarantee: the previous pair is removed before a scan runs, so absence of
 * the files reliably means the last scan did not succeed.
 */
class ReportInvalidationTest {

    private final ReportWriter writer = new ReportWriter();

    @TempDir
    Path tempDir;

    private static void write(Path path, String content) throws IOException {
        Files.writeString(path, content, StandardCharsets.UTF_8);
    }

    /** A directory containing a file cannot be deleted, so it blocks removal deterministically. */
    private static void obstruct(Path path) throws IOException {
        Files.createDirectories(path);
        write(path.resolve("occupant.txt"), "not ours");
    }

    // ---------- removal ----------

    @Test
    @DisplayName("both previous report files are removed")
    void bothTargetsRemoved() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        write(destination.jsonPath(), "PREVIOUS JSON");
        write(destination.markdownPath(), "PREVIOUS MARKDOWN");

        writer.invalidate(destination);

        assertFalse(Files.exists(destination.jsonPath()));
        assertFalse(Files.exists(destination.markdownPath()));
    }

    @Test
    @DisplayName("leftover temporaries from an interrupted run are removed too")
    void leftoverTemporariesRemoved() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        write(destination.jsonTempPath(), "INTERRUPTED");
        write(destination.markdownTempPath(), "INTERRUPTED");

        writer.invalidate(destination);

        assertFalse(Files.exists(destination.jsonTempPath()));
        assertFalse(Files.exists(destination.markdownTempPath()));
    }

    @Test
    @DisplayName("invalidating when only one file exists is fine")
    void partialPreviousStateRemoved() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        write(destination.jsonPath(), "ONLY JSON");

        writer.invalidate(destination);

        assertFalse(Files.exists(destination.jsonPath()));
    }

    // ---------- unrelated files are safe ----------

    @Test
    @DisplayName("unrelated files in the report directory are left alone")
    void unrelatedFilesSurvive() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        write(destination.jsonPath(), "PREVIOUS JSON");

        Path otherReport = tempDir.resolve("other-report.json");
        Path notes = tempDir.resolve("notes.md");
        Path archiveDir = tempDir.resolve("archive");
        Files.createDirectories(archiveDir);
        Path archived = archiveDir.resolve("last-week.json");
        write(otherReport, "someone else's file");
        write(notes, "hand-written notes");
        write(archived, "archived copy");

        writer.invalidate(destination);

        assertFalse(Files.exists(destination.jsonPath()), "the target should be gone");
        assertTrue(Files.exists(otherReport), "an unrelated JSON file must not be deleted");
        assertTrue(Files.exists(notes), "an unrelated Markdown file must not be deleted");
        assertTrue(Files.exists(archived), "a nested directory must not be touched");
    }

    @Test
    @DisplayName("a similarly named file is not mistaken for a target")
    void similarlyNamedFileSurvives() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        Path lookalike = tempDir.resolve("mend-actionable-vulnerabilities.json.bak");
        Path prefixed = tempDir.resolve("old-mend-actionable-vulnerabilities.json");
        write(lookalike, "backup someone made");
        write(prefixed, "renamed copy");

        writer.invalidate(destination);

        assertTrue(Files.exists(lookalike));
        assertTrue(Files.exists(prefixed));
    }

    // ---------- nothing to do ----------

    @Test
    @DisplayName("a missing directory is a silent success")
    void missingDirectoryIsSuccess() {
        ReportDestination destination = ReportDestination.into(tempDir.resolve("does-not-exist"));

        assertDoesNotThrow(() -> writer.invalidate(destination));
        assertFalse(Files.exists(destination.directory()),
                "invalidation should not create the directory");
    }

    @Test
    @DisplayName("an empty directory is a silent success")
    void emptyDirectoryIsSuccess() {
        assertDoesNotThrow(() -> writer.invalidate(ReportDestination.into(tempDir)));
    }

    @Test
    @DisplayName("invalidating twice is fine")
    void invalidatingTwiceIsFine() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        write(destination.jsonPath(), "PREVIOUS");

        writer.invalidate(destination);

        assertDoesNotThrow(() -> writer.invalidate(destination));
    }

    // ---------- blocked removal ----------

    @Test
    @DisplayName("a blocked target fails the invalidation so the scan cannot proceed")
    void blockedTargetFailsInvalidation() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        obstruct(destination.jsonPath());

        ReportWriteException thrown = assertThrows(ReportWriteException.class,
                () -> writer.invalidate(destination));

        assertFalse(thrown.pairStateGuaranteed());
        assertEquals(List.of(destination.jsonPath()), thrown.unreconciledPaths());
        assertTrue(thrown.getMessage().contains("cannot be guaranteed"),
                "the operator should be told the state is uncertain: " + thrown.getMessage());
    }

    @Test
    @DisplayName("removal of the second target still runs when the first is blocked")
    void removalContinuesPastABlockedTarget() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        obstruct(destination.jsonPath());
        write(destination.markdownPath(), "PREVIOUS MARKDOWN");

        assertThrows(ReportWriteException.class, () -> writer.invalidate(destination));

        // The JSON path is attempted first. Its failure must not abandon the Markdown file, or a
        // stale half of the pair would survive.
        assertFalse(Files.exists(destination.markdownPath()),
                "a blocked first path must not prevent the second being removed");
        assertTrue(Files.isDirectory(destination.jsonPath()),
                "the obstruction itself is never deleted");
    }

    @Test
    @DisplayName("both blocked targets are both reported")
    void bothBlockedTargetsReported() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        obstruct(destination.jsonPath());
        obstruct(destination.markdownPath());

        ReportWriteException thrown = assertThrows(ReportWriteException.class,
                () -> writer.invalidate(destination));

        assertEquals(List.of(destination.jsonPath(), destination.markdownPath()),
                thrown.unreconciledPaths());
        assertEquals(2, thrown.getSuppressed().length);
    }

    @Test
    @DisplayName("the failure message names the directory but no file content")
    void failureMessageIsSafe() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        obstruct(destination.jsonPath());
        write(destination.markdownPath(), "TOKEN-DO-NOT-LEAK-7b1c");

        ReportWriteException thrown = assertThrows(ReportWriteException.class,
                () -> writer.invalidate(destination));

        assertFalse(thrown.getMessage().contains("TOKEN-DO-NOT-LEAK-7b1c"));
        assertTrue(thrown.getMessage().contains(tempDir.toString()));
    }

    // ---------- interaction with publication ----------

    @Test
    @DisplayName("invalidate then publish leaves exactly the new pair")
    void invalidateThenPublish() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        write(destination.jsonPath(), "PREVIOUS JSON");
        write(destination.markdownPath(), "PREVIOUS MARKDOWN");

        writer.invalidate(destination);
        writer.publish(destination, "{\"new\":true}\n", "# New\n");

        assertEquals("{\"new\":true}\n",
                Files.readString(destination.jsonPath(), StandardCharsets.UTF_8));
        assertEquals("# New\n",
                Files.readString(destination.markdownPath(), StandardCharsets.UTF_8));
        try (var entries = Files.list(tempDir)) {
            assertEquals(2, entries.count(), "only the new pair should remain");
        }
    }
}
