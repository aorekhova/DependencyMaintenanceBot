package com.tungsten.depbot.report.actionable;

import com.tungsten.depbot.report.SecretRedactor;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Produces a copy of a report with every text field masked by a {@link SecretRedactor}.
 *
 * <p><strong>This runs before rendering, and that ordering is the whole point.</strong> Replacing a
 * secret in already-rendered JSON does not work, because JSON escaping rewrites the characters: a
 * credential containing a double quote is written as {@code \"} and one containing a newline as
 * {@code \n}, so a search for the original bytes finds nothing and the secret ships in a file that
 * looks correctly redacted. Masking the model first means the renderers never receive the secret.
 *
 * <p>The field that makes this necessary rather than merely prudent is text Mend authors — a fix
 * {@code message} or a {@code description} is not written by this application and could echo back a
 * submitted token.
 *
 * <p>Instances are immutable, and the report passed in is never modified; a new graph is returned.
 *
 * <p>Report metadata ({@code generatedAt}, {@code reportVersion}) is redacted too, for uniformity of
 * the rule "every string field is masked". Being straight about it: both values are authored by this
 * application and cannot contain a credential, so redacting them is consistency rather than a real
 * defence.
 */
public final class ActionableReportRedactor {

    private final SecretRedactor redactor;

    public ActionableReportRedactor(SecretRedactor redactor) {
        this.redactor = Objects.requireNonNull(redactor, "redactor");
    }

    /** A redactor that knows no secrets and therefore changes nothing. */
    public static ActionableReportRedactor none() {
        return new ActionableReportRedactor(SecretRedactor.none());
    }

    /** Builds one seeded with the given secret values. */
    public static ActionableReportRedactor withSecrets(String... secrets) {
        return new ActionableReportRedactor(SecretRedactor.of(secrets));
    }

    public ActionableReport redact(ActionableReport report) {
        if (report == null) {
            return null;
        }
        return new ActionableReport(
                mask(report.generatedAt()),
                mask(report.reportVersion()),
                report.summary(),
                redactFindings(report.findings()));
    }

    private List<ActionableFinding> redactFindings(List<ActionableFinding> findings) {
        if (findings == null || findings.isEmpty()) {
            return List.of();
        }
        List<ActionableFinding> redacted = new ArrayList<>(findings.size());
        for (ActionableFinding finding : findings) {
            redacted.add(redactFinding(finding));
        }
        return List.copyOf(redacted);
    }

    private ActionableFinding redactFinding(ActionableFinding finding) {
        return new ActionableFinding(
                mask(finding.vulnerabilityId()),
                mask(finding.type()),
                mask(finding.severity()),
                mask(finding.cvss3Severity()),
                mask(finding.cvss3Score()),
                finding.cvss3ScoreNumeric(),
                mask(finding.score()),
                mask(finding.scoreMetadataVector()),
                mask(finding.description()),
                mask(finding.publishedDate()),
                mask(finding.lastUpdatedDate()),
                mask(finding.referenceUrl()),
                mask(finding.product()),
                mask(finding.project()),
                redactLibrary(finding.library()),
                redactLocations(finding.locations()),
                redactRemediation(finding.remediation()));
    }

    private AffectedLibrary redactLibrary(AffectedLibrary library) {
        if (library == null) {
            return null;
        }
        return new AffectedLibrary(
                mask(library.groupId()),
                mask(library.artifactId()),
                mask(library.version()),
                mask(library.coordinates()),
                mask(library.name()),
                mask(library.filename()),
                mask(library.type()),
                mask(library.sha1()),
                mask(library.keyUuid()),
                mask(library.architecture()),
                mask(library.languageVersion()),
                mask(library.description()));
    }

    private List<FindingLocation> redactLocations(List<FindingLocation> locations) {
        if (locations == null || locations.isEmpty()) {
            return List.of();
        }
        List<FindingLocation> redacted = new ArrayList<>(locations.size());
        for (FindingLocation location : locations) {
            redacted.add(new FindingLocation(mask(location.path()), mask(location.matchType())));
        }
        return List.copyOf(redacted);
    }

    private Remediation redactRemediation(Remediation remediation) {
        if (remediation == null) {
            return Remediation.empty();
        }
        return new Remediation(
                redactFix(remediation.topFix()),
                redactFixes(remediation.allFixes()));
    }

    private List<RecommendedFix> redactFixes(List<RecommendedFix> fixes) {
        if (fixes == null || fixes.isEmpty()) {
            return List.of();
        }
        List<RecommendedFix> redacted = new ArrayList<>(fixes.size());
        for (RecommendedFix fix : fixes) {
            redacted.add(redactFix(fix));
        }
        return List.copyOf(redacted);
    }

    private RecommendedFix redactFix(RecommendedFix fix) {
        if (fix == null) {
            return null;
        }
        return new RecommendedFix(
                mask(fix.vulnerability()),
                mask(fix.type()),
                mask(fix.origin()),
                mask(fix.url()),
                mask(fix.fixResolution()),
                mask(fix.date()),
                mask(fix.message()));
    }

    private String mask(String value) {
        return redactor.redact(value);
    }
}
