package com.tungsten.depbot.mend.history;

import java.util.List;
import java.util.Objects;

/**
 * The run-independent ledger of every distinct Mend snapshot fingerprint ever seen, at
 * {@code reports/mend-history/index.json}.
 *
 * <p>Rewritten in full on every scan -- a repeat fingerprint only has its {@link Entry#lastSeenAt()}/
 * {@link Entry#seenCount()} bumped; a new fingerprint gets a new {@link Entry} appended -- the same
 * "rewritten as it progresses" idiom {@code RunManifest} already uses, except this index spans every
 * run rather than just one.
 */
public record MendHistoryIndex(String schemaVersion, List<Entry> entries) {

    public static final String CURRENT_VERSION = "1.0";

    public MendHistoryIndex {
        schemaVersion = (schemaVersion == null || schemaVersion.isBlank()) ? CURRENT_VERSION : schemaVersion;
        entries = entries == null ? List.of() : List.copyOf(entries);
    }

    /** An empty index -- what a first-ever scan reads when no history store exists yet. */
    public static MendHistoryIndex empty() {
        return new MendHistoryIndex(CURRENT_VERSION, List.of());
    }

    /** One distinct fingerprint's history: when it was first/last seen, and where its snapshot lives. */
    public record Entry(
            String fingerprint,
            String firstSeenAt,
            String lastSeenAt,
            int seenCount,
            int findingCount,
            String snapshotPath) {

        public Entry {
            Objects.requireNonNull(fingerprint, "fingerprint");
            Objects.requireNonNull(snapshotPath, "snapshotPath");
        }
    }
}
