package com.tungsten.depbot.mend.history;

import com.tungsten.depbot.report.actionable.ActionableFinding;
import com.tungsten.depbot.report.actionable.AffectedLibrary;
import com.tungsten.depbot.report.actionable.Remediation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MendSnapshotHistoryServiceTest {

    @TempDir
    Path root;

    private static ActionableFinding finding(String id, String artifactId) {
        AffectedLibrary library = new AffectedLibrary("com.example", artifactId, "1.0.0",
                "com.example:" + artifactId + ":1.0.0", artifactId, artifactId + ".jar",
                "JAVA_ARCHIVE", "0000000000000000000000000000000000000001", "uuid", "", "", "");
        return new ActionableFinding(id, "SECURITY_VULNERABILITY", "HIGH", "high", "8.1", 8.1,
                "8.1", "AV:N", "desc", "2020-01-01", "2020-02-02", "https://example.invalid/ref",
                "product", "project", library, List.of(), Remediation.empty());
    }

    private MendSnapshotHistoryService service() {
        return new MendSnapshotHistoryService(root);
    }

    @Test
    @DisplayName("the first record() creates a snapshot file and an index entry")
    void firstRecordCreatesSnapshotAndIndexEntry() throws IOException {
        List<ActionableFinding> findings = List.of(finding("CVE-1", "lib-a"));

        MendSnapshotHistoryService.MendSnapshotReference reference =
                service().record(findings, Instant.parse("2026-01-01T00:00:00Z"));

        assertTrue(reference.isNewSnapshot());
        Path snapshotPath = Path.of(reference.snapshotPath());
        assertTrue(Files.exists(snapshotPath));
        assertTrue(Files.exists(root.resolve("index.json")));

        String indexContent = Files.readString(root.resolve("index.json"), StandardCharsets.UTF_8);
        assertTrue(indexContent.contains(reference.fingerprint()));
        assertTrue(indexContent.contains("\"seenCount\" : 1"));
    }

    @Test
    @DisplayName("an identical repeat never rewrites the snapshot file, only bumps the index")
    void identicalRepeatDoesNotRewriteSnapshot() throws IOException {
        List<ActionableFinding> findings = List.of(finding("CVE-1", "lib-a"));
        MendSnapshotHistoryService service = service();

        MendSnapshotHistoryService.MendSnapshotReference first =
                service.record(findings, Instant.parse("2026-01-01T00:00:00Z"));
        String firstContent = Files.readString(Path.of(first.snapshotPath()), StandardCharsets.UTF_8);

        MendSnapshotHistoryService.MendSnapshotReference second =
                service.record(findings, Instant.parse("2026-01-02T00:00:00Z"));

        assertEquals(first.fingerprint(), second.fingerprint());
        assertEquals(first.snapshotPath(), second.snapshotPath());
        assertTrue(!second.isNewSnapshot());

        String secondContent = Files.readString(Path.of(second.snapshotPath()), StandardCharsets.UTF_8);
        assertEquals(firstContent, secondContent, "the snapshot file itself must never be rewritten");

        String indexContent = Files.readString(root.resolve("index.json"), StandardCharsets.UTF_8);
        assertTrue(indexContent.contains("\"seenCount\" : 2"));
        assertTrue(indexContent.contains("2026-01-01T00:00:00Z"), "firstSeenAt must be preserved");
        assertTrue(indexContent.contains("2026-01-02T00:00:00Z"), "lastSeenAt must be updated");

        try (var snapshotFiles = Files.list(root.resolve("snapshots"))) {
            assertEquals(1, snapshotFiles.count(), "an identical snapshot must never be duplicated");
        }
    }

    @Test
    @DisplayName("genuinely different content creates a second, distinct, preserved snapshot")
    void differentContentCreatesSecondSnapshot() throws IOException {
        MendSnapshotHistoryService service = service();
        MendSnapshotHistoryService.MendSnapshotReference first =
                service.record(List.of(finding("CVE-1", "lib-a")), Instant.parse("2026-01-01T00:00:00Z"));
        MendSnapshotHistoryService.MendSnapshotReference second =
                service.record(List.of(finding("CVE-2", "lib-b")), Instant.parse("2026-01-02T00:00:00Z"));

        assertNotEquals(first.fingerprint(), second.fingerprint());
        assertTrue(second.isNewSnapshot());
        assertTrue(Files.exists(Path.of(first.snapshotPath())), "the first snapshot must still exist");
        assertTrue(Files.exists(Path.of(second.snapshotPath())), "the second snapshot must exist");

        try (var snapshotFiles = Files.list(root.resolve("snapshots"))) {
            assertEquals(2, snapshotFiles.count());
        }
    }

    @Test
    @DisplayName("an absent index is treated as empty, not an error")
    void absentIndexTreatedAsEmpty() {
        assertTrue(!Files.exists(root.resolve("index.json")));

        MendSnapshotHistoryService.MendSnapshotReference reference =
                service().record(List.of(finding("CVE-1", "lib-a")), Instant.parse("2026-01-01T00:00:00Z"));

        assertTrue(reference.isNewSnapshot());
    }
}
