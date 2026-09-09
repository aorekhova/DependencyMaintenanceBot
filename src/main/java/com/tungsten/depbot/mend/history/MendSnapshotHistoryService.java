package com.tungsten.depbot.mend.history;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.report.actionable.ActionableFinding;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Persists Mend vulnerability snapshots historically, without ever physically duplicating an
 * identical one.
 *
 * <p>Content-addressed by {@link MendSnapshotFingerprint#compute}: a fingerprint already present in
 * {@code <root>/index.json} means an identical snapshot was seen before, so only the index entry's
 * {@code lastSeenAt}/{@code seenCount} are updated -- the snapshot file itself, once written, is
 * never rewritten again. A new fingerprint gets its own immutable
 * {@code <root>/snapshots/<fingerprint>.json} plus a new index entry. Nothing here ever needs manual
 * cleanup between runs: every write is either "append a ledger entry" or "write a new
 * content-addressed file that can never collide with an existing one."
 */
public final class MendSnapshotHistoryService {

    private static final String SNAPSHOTS_DIRECTORY = "snapshots";
    private static final String INDEX_FILE_NAME = "index.json";

    private final Path root;
    private final JsonMapper mapper = JsonMapper.builder().build();
    private final MendSnapshotJsonRenderer snapshotRenderer = new MendSnapshotJsonRenderer();
    private final MendHistoryIndexJsonRenderer indexRenderer = new MendHistoryIndexJsonRenderer();

    public MendSnapshotHistoryService(Path root) {
        this.root = Objects.requireNonNull(root, "root");
    }

    /**
     * Records this snapshot in history, deduplicating by content fingerprint.
     *
     * @throws MendHistoryException if the history store could not be read or written
     */
    public MendSnapshotReference record(List<ActionableFinding> findings, Instant now) {
        List<ActionableFinding> input = findings == null ? List.of() : findings;
        String fingerprint = MendSnapshotFingerprint.compute(input);
        String timestamp = now.toString();

        MendHistoryIndex index = readIndex();
        MendHistoryIndex.Entry existing = findEntry(index, fingerprint);

        if (existing != null) {
            MendHistoryIndex updated = withUpdatedEntry(index, existing, timestamp);
            writeIndex(updated);
            return new MendSnapshotReference(fingerprint, existing.snapshotPath(), existing.firstSeenAt(), false);
        }

        Path snapshotPath = snapshotsDirectory().resolve(fingerprint + ".json");
        MendSnapshot snapshot = new MendSnapshot(
                MendSnapshot.CURRENT_VERSION, fingerprint, timestamp, input.size(), input);
        writeSnapshot(snapshotPath, snapshot);

        MendHistoryIndex.Entry newEntry = new MendHistoryIndex.Entry(
                fingerprint, timestamp, timestamp, 1, input.size(), snapshotPath.toString());
        List<MendHistoryIndex.Entry> entries = new ArrayList<>(index.entries());
        entries.add(newEntry);
        writeIndex(new MendHistoryIndex(MendHistoryIndex.CURRENT_VERSION, entries));

        return new MendSnapshotReference(fingerprint, snapshotPath.toString(), timestamp, true);
    }

    private Path snapshotsDirectory() {
        return root.resolve(SNAPSHOTS_DIRECTORY);
    }

    private Path indexPath() {
        return root.resolve(INDEX_FILE_NAME);
    }

    private static MendHistoryIndex.Entry findEntry(MendHistoryIndex index, String fingerprint) {
        for (MendHistoryIndex.Entry entry : index.entries()) {
            if (entry.fingerprint().equals(fingerprint)) {
                return entry;
            }
        }
        return null;
    }

    private static MendHistoryIndex withUpdatedEntry(
            MendHistoryIndex index, MendHistoryIndex.Entry existing, String seenAt) {
        List<MendHistoryIndex.Entry> entries = new ArrayList<>(index.entries().size());
        for (MendHistoryIndex.Entry entry : index.entries()) {
            if (entry == existing) {
                entries.add(new MendHistoryIndex.Entry(
                        entry.fingerprint(), entry.firstSeenAt(), seenAt,
                        entry.seenCount() + 1, entry.findingCount(), entry.snapshotPath()));
            } else {
                entries.add(entry);
            }
        }
        return new MendHistoryIndex(index.schemaVersion(), entries);
    }

    private MendHistoryIndex readIndex() {
        Path path = indexPath();
        if (!Files.exists(path)) {
            return MendHistoryIndex.empty();
        }
        String content;
        try {
            content = Files.readString(path, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new MendHistoryException("Could not read " + path, e);
        }
        try {
            return mapper.readValue(content, MendHistoryIndex.class);
        } catch (JsonProcessingException e) {
            throw new MendHistoryException("Could not parse " + path + " as a Mend history index", e);
        }
    }

    private void writeIndex(MendHistoryIndex index) {
        Path path = indexPath();
        try {
            Files.createDirectories(path.getParent());
            Files.writeString(path, indexRenderer.render(index), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new MendHistoryException("Could not write " + path, e);
        }
    }

    private void writeSnapshot(Path path, MendSnapshot snapshot) {
        try {
            Files.createDirectories(path.getParent());
            Files.writeString(path, snapshotRenderer.render(snapshot), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new MendHistoryException("Could not write " + path, e);
        }
    }

    /** What a caller needs after recording: the fingerprint, where its snapshot lives, and whether it was new. */
    public record MendSnapshotReference(
            String fingerprint, String snapshotPath, String firstSeenAt, boolean isNewSnapshot) {
    }
}
