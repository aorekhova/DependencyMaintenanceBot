package com.tungsten.depbot.report.actionable;

import com.tungsten.depbot.Fixtures;
import com.tungsten.depbot.mend.MendResponseParser;
import com.tungsten.depbot.mend.model.VulnerabilityRecord;
import com.tungsten.depbot.report.SeverityCounts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers the guarantee that the two fixed filenames can never represent different generations.
 *
 * <p>The "second file fails to publish" scenarios use an injected move operation. Reproducing that
 * through the filesystem alone would depend on platform behaviour and permissions, and a flaky test
 * of this particular guarantee would be worse than none.
 */
class ReportPublicationTest {

    private static final String JSON = "{\n  \"generatedAt\" : \"2026-01-02T03:04:05Z\"\n}\n";
    private static final String MARKDOWN = "# Report\n\n- Generated at: 2026-01-02T03:04:05Z\n";

    @TempDir
    Path tempDir;

    /** Fails on the nth move, delegating to the real filesystem otherwise. */
    private static ReportWriter.FileMoveOperation failOnMove(int failingCall) {
        return new ReportWriter.FileMoveOperation() {
            private int calls;

            @Override
            public void move(Path source, Path target, CopyOption... options) throws IOException {
                if (++calls == failingCall) {
                    throw new IOException("synthetic publication failure");
                }
                Files.move(source, target, options);
            }
        };
    }

    /** A directory containing a file cannot be deleted, so it blocks cleanup deterministically. */
    private static void obstruct(Path path) throws IOException {
        Files.createDirectories(path);
        Files.writeString(path.resolve("occupant.txt"), "not ours", StandardCharsets.UTF_8);
    }

    private static List<String> tempFiles(Path directory) throws IOException {
        try (var entries = Files.list(directory)) {
            return entries.map(p -> p.getFileName().toString())
                    .filter(name -> name.endsWith(".tmp"))
                    .toList();
        }
    }

    // ---------- the pair is consistent ----------

    @Test
    @DisplayName("both files carry the same generatedAt and reportVersion")
    void bothFilesShareTheSameGeneration() throws IOException {
        List<VulnerabilityRecord> vulnerabilities = new MendResponseParser()
                .parse(Fixtures.load("actionable-full-detail.json")).vulnerabilities();

        ActionableReport report = new ActionableReportFactory(
                Clock.fixed(Instant.parse("2026-01-02T03:04:05Z"), ZoneOffset.UTC))
                .build(vulnerabilities, SeverityCounts.from(vulnerabilities));

        ReportDestination destination = ReportDestination.into(tempDir);
        WrittenReports written = new ReportWriter().publish(destination,
                new JsonReportRenderer().render(report),
                new MarkdownReportRenderer().render(report));

        String json = Files.readString(written.jsonPath(), StandardCharsets.UTF_8);
        String markdown = Files.readString(written.markdownPath(), StandardCharsets.UTF_8);

        assertTrue(json.contains("2026-01-02T03:04:05Z"));
        assertTrue(markdown.contains("2026-01-02T03:04:05Z"));
        assertTrue(json.contains("\"reportVersion\" : \"1.1\""));
        assertTrue(markdown.contains("- Report version: 1.1"));
    }

    // ---------- second file fails, cleanup succeeds ----------

    @Test
    @DisplayName("when the second file fails to publish, neither target is left behind")
    void secondFileFailureRemovesBothTargets() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        ReportWriter writer = new ReportWriter(failOnMove(2));

        ReportWriteException thrown = assertThrows(ReportWriteException.class,
                () -> writer.publish(destination, JSON, MARKDOWN));

        assertFalse(Files.exists(destination.jsonPath()),
                "the JSON was published then must have been removed again");
        assertFalse(Files.exists(destination.markdownPath()));
        assertTrue(thrown.pairStateGuaranteed(),
                "cleanup succeeded, so the state should be reported as known");
        assertTrue(thrown.unreconciledPaths().isEmpty());
        assertTrue(tempFiles(tempDir).isEmpty(), "temporaries should not survive");
    }

    @Test
    @DisplayName("when the first file fails to publish, nothing is left behind")
    void firstFileFailureLeavesNothing() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        ReportWriter writer = new ReportWriter(failOnMove(1));

        ReportWriteException thrown = assertThrows(ReportWriteException.class,
                () -> writer.publish(destination, JSON, MARKDOWN));

        assertFalse(Files.exists(destination.jsonPath()));
        assertFalse(Files.exists(destination.markdownPath()));
        assertTrue(thrown.pairStateGuaranteed());
        assertTrue(tempFiles(tempDir).isEmpty());
    }

    @Test
    @DisplayName("a previous generation is removed rather than restored")
    void previousGenerationIsNotRestored() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        Files.writeString(destination.jsonPath(), "PREVIOUS JSON", StandardCharsets.UTF_8);
        Files.writeString(destination.markdownPath(), "PREVIOUS MARKDOWN", StandardCharsets.UTF_8);

        assertThrows(ReportWriteException.class,
                () -> new ReportWriter(failOnMove(2)).publish(destination, JSON, MARKDOWN));

        // Restoring the old pair would reinstate exactly the stale files invalidation exists to
        // eliminate, so removal is the correct rollback.
        assertFalse(Files.exists(destination.jsonPath()));
        assertFalse(Files.exists(destination.markdownPath()));
    }

    // ---------- second file fails and cleanup is blocked ----------

    @Test
    @DisplayName("when cleanup of one target is blocked, the pair state is reported as unknown")
    void blockedCleanupReportsUnknownState() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        obstruct(destination.markdownPath());

        ReportWriteException thrown = assertThrows(ReportWriteException.class,
                () -> new ReportWriter(failOnMove(2)).publish(destination, JSON, MARKDOWN));

        assertFalse(thrown.pairStateGuaranteed(),
                "cleanup was blocked, so the state must not be claimed as known");
        assertEquals(List.of(destination.markdownPath()), thrown.unreconciledPaths());
        assertTrue(thrown.getMessage().contains("removed"),
                "the message should explain what was attempted: " + thrown.getMessage());
    }

    @Test
    @DisplayName("cleanup continues past a blocked path and still reconciles the others")
    void cleanupContinuesPastFailure() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        obstruct(destination.markdownPath());

        assertThrows(ReportWriteException.class,
                () -> new ReportWriter(failOnMove(2)).publish(destination, JSON, MARKDOWN));

        // The JSON target comes first in the sweep; the blocked Markdown path must not stop it.
        assertFalse(Files.exists(destination.jsonPath()),
                "a blocked path must not prevent the others being cleaned");
        assertTrue(tempFiles(tempDir).isEmpty(), "temporaries were still swept");
    }

    @Test
    @DisplayName("an obstruction that is not ours is never deleted")
    void obstructionIsLeftUntouched() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        obstruct(destination.markdownPath());

        assertThrows(ReportWriteException.class,
                () -> new ReportWriter(failOnMove(2)).publish(destination, JSON, MARKDOWN));

        assertTrue(Files.isDirectory(destination.markdownPath()));
        assertTrue(Files.exists(destination.markdownPath().resolve("occupant.txt")),
                "the writer must not delete files it did not create");
    }

    @Test
    @DisplayName("cleanup failures are attached as suppressed exceptions, not printed")
    void cleanupFailuresAreAttached() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);
        obstruct(destination.markdownPath());

        ReportWriteException thrown = assertThrows(ReportWriteException.class,
                () -> new ReportWriter(failOnMove(2)).publish(destination, JSON, MARKDOWN));

        assertEquals(1, thrown.getSuppressed().length,
                "the blocked deletion should be retained for debugging");
        assertTrue(thrown.getSuppressed()[0] instanceof IOException);
        assertFalse(thrown.getMessage().contains("occupant.txt"),
                "the message should name only the report path, not directory contents");
    }

    // ---------- no partial file ever visible ----------

    @Test
    @DisplayName("a failure while writing a temporary publishes nothing")
    void temporaryWriteFailurePublishesNothing() throws IOException {
        // Obstructing the JSON temporary path makes writeString fail before any publication.
        ReportDestination destination = ReportDestination.into(tempDir);
        obstruct(destination.jsonTempPath());

        ReportWriteException thrown = assertThrows(ReportWriteException.class,
                () -> new ReportWriter().publish(destination, JSON, MARKDOWN));

        assertFalse(Files.exists(destination.jsonPath()));
        assertFalse(Files.exists(destination.markdownPath()));
        assertTrue(thrown.getMessage().contains("temporary"));
    }

    @Test
    @DisplayName("no partial content is ever visible under a fixed report name")
    void noPartialContentUnderFixedName() throws IOException {
        ReportDestination destination = ReportDestination.into(tempDir);

        assertThrows(ReportWriteException.class,
                () -> new ReportWriter(failOnMove(2)).publish(destination, JSON, MARKDOWN));

        // Either a complete file or no file. Never a half-written one.
        assertFalse(Files.exists(destination.jsonPath()));
        assertFalse(Files.exists(destination.markdownPath()));
    }

    @Test
    @DisplayName("a successful publication reports both paths")
    void successReportsBothPaths() {
        ReportDestination destination = ReportDestination.into(tempDir);

        WrittenReports written = new ReportWriter().publish(destination, JSON, MARKDOWN);

        assertEquals(destination.jsonPath(), written.jsonPath());
        assertEquals(destination.markdownPath(), written.markdownPath());
    }
}
