package com.tungsten.depbot.mend.history;

import com.tungsten.depbot.report.actionable.ActionableFinding;
import com.tungsten.depbot.report.actionable.AffectedLibrary;
import com.tungsten.depbot.report.actionable.RecommendedFix;
import com.tungsten.depbot.report.actionable.Remediation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;

/**
 * A deterministic, order-independent fingerprint of a Mend vulnerability snapshot's meaningful
 * content -- the identity two scans of the same underlying vulnerabilities must share, regardless of
 * Mend's own response ordering or of volatile metadata that can change without the vulnerabilities
 * themselves having changed.
 *
 * <p>Operates on the published, already-redacted {@link ActionableFinding} model (never the raw Mend
 * integration model) -- see {@code com.tungsten.depbot.report.actionable.ActionableReportService},
 * which computes this fingerprint strictly after {@code ActionableReportRedactor} has run, so a
 * persisted snapshot can never carry pre-redaction content.
 *
 * <p><strong>Included</strong> (per finding): {@code vulnerabilityId, type, severity, cvss3Severity,
 * cvss3Score, cvss3ScoreNumeric, score, scoreMetadataVector, description, referenceUrl, product,
 * project}; every {@link AffectedLibrary} field; every {@link RecommendedFix} field of both
 * {@code topFix} and {@code allFixes}.
 *
 * <p><strong>Excluded</strong>: {@code publishedDate}, {@code lastUpdatedDate} (Mend can touch these
 * without the vulnerability itself changing) and {@code locations} (host-specific filesystem paths
 * from whichever machine ran the scan) -- nothing else.
 *
 * <p><strong>Order-independence</strong>: findings are sorted by {@code (vulnerabilityId, library
 * coordinates, full canonical per-finding string)} before hashing, and each finding's own
 * {@code allFixes} list is independently sorted by its fixes' own canonical strings -- Mend's array
 * order, in either place, is never part of the identity.
 *
 * <p>Every field value is length-prefix encoded ({@code  N} for {@code null}, {@code
 *  S<length>:<value>} otherwise) before being concatenated, so no two distinct inputs can ever
 * collide onto the same canonical string merely because one value happens to contain a delimiter
 * that appears elsewhere.
 */
public final class MendSnapshotFingerprint {

    private static final char NULL_MARKER = 'N';
    private static final char VALUE_MARKER = 'S';
    private static final char FIELD_SEPARATOR = ' ';
    private static final char FIX_SEPARATOR = '\u0002';
    private static final char FINDING_SEPARATOR = '\n';

    private MendSnapshotFingerprint() {
    }

    public static String compute(List<ActionableFinding> findings) {
        List<ActionableFinding> input = findings == null ? List.of() : findings;

        List<String> canonicalPerFinding = new ArrayList<>(input.size());
        for (ActionableFinding finding : input) {
            canonicalPerFinding.add(canonicalize(finding));
        }

        List<FindingSortKey> sortKeys = new ArrayList<>(input.size());
        for (int i = 0; i < input.size(); i++) {
            ActionableFinding finding = input.get(i);
            String coordinates = finding.library() == null ? null : finding.library().coordinates();
            sortKeys.add(new FindingSortKey(finding.vulnerabilityId(), coordinates, canonicalPerFinding.get(i)));
        }

        sortKeys.sort(Comparator
                .comparing(FindingSortKey::vulnerabilityId, Comparator.nullsFirst(Comparator.naturalOrder()))
                .thenComparing(FindingSortKey::libraryCoordinates, Comparator.nullsFirst(Comparator.naturalOrder()))
                .thenComparing(FindingSortKey::canonical, Comparator.nullsFirst(Comparator.naturalOrder())));

        StringBuilder joined = new StringBuilder();
        for (int i = 0; i < sortKeys.size(); i++) {
            if (i > 0) {
                joined.append(FINDING_SEPARATOR);
            }
            joined.append(sortKeys.get(i).canonical());
        }

        return sha256Hex(joined.toString());
    }

    private static String canonicalize(ActionableFinding finding) {
        StringBuilder sb = new StringBuilder();
        field(sb, finding.vulnerabilityId());
        field(sb, finding.type());
        field(sb, finding.severity());
        field(sb, finding.cvss3Severity());
        field(sb, finding.cvss3Score());
        field(sb, finding.cvss3ScoreNumeric() == null ? null : String.valueOf(finding.cvss3ScoreNumeric()));
        field(sb, finding.score());
        field(sb, finding.scoreMetadataVector());
        field(sb, finding.description());
        field(sb, finding.referenceUrl());
        field(sb, finding.product());
        field(sb, finding.project());
        canonicalizeLibrary(sb, finding.library());
        canonicalizeRemediation(sb, finding.remediation());
        return sb.toString();
    }

    private static void canonicalizeLibrary(StringBuilder sb, AffectedLibrary library) {
        if (library == null) {
            field(sb, (String) null);
            return;
        }
        field(sb, library.groupId());
        field(sb, library.artifactId());
        field(sb, library.version());
        field(sb, library.coordinates());
        field(sb, library.name());
        field(sb, library.filename());
        field(sb, library.type());
        field(sb, library.sha1());
        field(sb, library.keyUuid());
        field(sb, library.architecture());
        field(sb, library.languageVersion());
        field(sb, library.description());
    }

    private static void canonicalizeRemediation(StringBuilder sb, Remediation remediation) {
        if (remediation == null) {
            field(sb, (String) null);
            return;
        }
        canonicalizeFix(sb, remediation.topFix());

        List<String> fixStrings = new ArrayList<>(remediation.allFixes().size());
        for (RecommendedFix fix : remediation.allFixes()) {
            StringBuilder fixSb = new StringBuilder();
            canonicalizeFix(fixSb, fix);
            fixStrings.add(fixSb.toString());
        }
        fixStrings.sort(Comparator.nullsFirst(Comparator.naturalOrder()));
        for (int i = 0; i < fixStrings.size(); i++) {
            if (i > 0) {
                sb.append(FIX_SEPARATOR);
            }
            sb.append(fixStrings.get(i));
        }
    }

    private static void canonicalizeFix(StringBuilder sb, RecommendedFix fix) {
        if (fix == null) {
            field(sb, (String) null);
            return;
        }
        field(sb, fix.vulnerability());
        field(sb, fix.type());
        field(sb, fix.origin());
        field(sb, fix.url());
        field(sb, fix.fixResolution());
        field(sb, fix.date());
        field(sb, fix.message());
    }

    private static void field(StringBuilder sb, String value) {
        sb.append(FIELD_SEPARATOR);
        if (value == null) {
            sb.append(NULL_MARKER);
        } else {
            sb.append(VALUE_MARKER).append(value.length()).append(':').append(value);
        }
    }

    private static String sha256Hex(String canonical) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(canonical.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available in this JVM", e);
        }
    }

    private record FindingSortKey(String vulnerabilityId, String libraryCoordinates, String canonical) {
    }
}
