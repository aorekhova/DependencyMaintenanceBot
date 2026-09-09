package com.tungsten.depbot.mend.history;

import com.tungsten.depbot.report.actionable.ActionableFinding;

import java.util.List;

/**
 * One distinct Mend vulnerability snapshot, content-addressed by its own {@link #fingerprint()}.
 *
 * <p>Written once per distinct fingerprint at {@code reports/mend-history/snapshots/<fingerprint>.json}
 * and never rewritten again -- a repeat scan that produces an identical fingerprint only touches
 * {@link MendHistoryIndex}, never this file. {@code findings} are already redacted: this store never
 * holds pre-redaction content, exactly like the current-scan report pair it is built alongside.
 */
public record MendSnapshot(
        String schemaVersion,
        String fingerprint,
        String firstCapturedAt,
        int findingCount,
        List<ActionableFinding> findings) {

    public static final String CURRENT_VERSION = "1.0";

    public MendSnapshot {
        schemaVersion = (schemaVersion == null || schemaVersion.isBlank()) ? CURRENT_VERSION : schemaVersion;
        findings = findings == null ? List.of() : List.copyOf(findings);
    }
}
