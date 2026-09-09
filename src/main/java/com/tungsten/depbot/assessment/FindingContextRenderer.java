package com.tungsten.depbot.assessment;

import com.tungsten.depbot.report.SecretRedactor;
import com.tungsten.depbot.report.actionable.ActionableFinding;
import com.tungsten.depbot.report.actionable.AffectedLibrary;
import com.tungsten.depbot.report.actionable.FindingLocation;
import com.tungsten.depbot.report.actionable.RecommendedFix;
import com.tungsten.depbot.report.actionable.Remediation;

import java.util.List;
import java.util.Objects;

/**
 * Writes out everything Mend reported about one library, in full, as Markdown.
 *
 * <p>Shared by both phases on purpose. The implementation is not given a digest of the problem it is
 * fixing -- it gets the same complete evidence the assessment worked from, so it can recognise for
 * itself when the branch in front of it does not match what the assessment concluded. Handing phase two
 * only a plan and a version is precisely the shape of the failed pilot.
 *
 * <p>Nothing is ever summarised or inferred. Every fix Mend listed is present, alternatives included: a
 * set of fix versions spanning several parallel release branches is the single most informative thing
 * about a finding like the jackson-databind one, and it only exists in the alternatives. A field Mend
 * did not supply reads {@code Not provided} rather than being filled in with a guess.
 *
 * <p>Every Mend-authored string passes through a {@link SecretRedactor}, because these prompts are
 * written to disk and Mend text can echo a submitted credential back.
 */
public final class FindingContextRenderer {

    /** How an absent value reads in a prompt. Shared so both phases say the same thing. */
    public static final String NOT_PROVIDED = "Not provided";

    private final SecretRedactor redactor;

    public FindingContextRenderer(SecretRedactor redactor) {
        this.redactor = Objects.requireNonNull(redactor, "redactor");
    }

    /** Appends the whole finding context for {@code workItem}, heading included. */
    public void appendTo(List<String> lines, VulnerabilityWorkItem workItem) {
        Objects.requireNonNull(lines, "lines");
        Objects.requireNonNull(workItem, "workItem");

        lines.add("## What Mend reported");
        lines.add("");
        lines.add("- Library: " + workItem.coordinates());
        lines.add("- Version Mend reported: " + text(workItem.reportedVersion()));
        lines.add("- Highest severity across its findings: " + text(workItem.maxSeverity()));
        lines.add("- Target version this bot computed: " + text(workItem.botComputedTargetVersion())
                + " -- **unverified.** It was derived mechanically from the fix text below, with no "
                + "knowledge of this repository. It has previously been a downgrade. Treat it as one more "
                + "piece of evidence, and contradict it if the repository says otherwise.");
        lines.add("");

        if (workItem.findings().isEmpty()) {
            lines.add("No individual findings were supplied with this item.");
            lines.add("");
            return;
        }

        lines.add("Every finding Mend raised against this library follows, in full.");
        lines.add("");
        for (ActionableFinding finding : workItem.findings()) {
            appendOneFinding(lines, finding);
        }
    }

    private void appendOneFinding(List<String> lines, ActionableFinding finding) {
        lines.add("### " + text(finding.vulnerabilityId()));
        lines.add("");
        lines.add("- Severity: " + text(finding.severity()));
        lines.add("- Type: " + text(finding.type()));
        lines.add("- CVSS 3 severity: " + text(finding.cvss3Severity()));
        lines.add("- CVSS 3 score: " + text(finding.cvss3Score()));
        lines.add("- Score: " + text(finding.score()));
        lines.add("- Score vector: " + text(finding.scoreMetadataVector()));
        lines.add("- Published: " + text(finding.publishedDate()));
        lines.add("- Last updated: " + text(finding.lastUpdatedDate()));
        lines.add("- Reference: " + text(finding.referenceUrl()));
        lines.add("- Mend product: " + text(finding.product()));
        lines.add("- Mend project: " + text(finding.project()));
        lines.add("");
        lines.add("Description:");
        lines.add("");
        lines.add(text(finding.description()));
        lines.add("");
        appendLibrary(lines, finding.library());
        appendLocations(lines, finding.locations());
        appendRemediation(lines, finding.remediation());
    }

    private void appendLibrary(List<String> lines, AffectedLibrary library) {
        lines.add("Library as Mend identified it:");
        lines.add("");
        if (library == null) {
            lines.add("- " + NOT_PROVIDED);
            lines.add("");
            return;
        }
        lines.add("- groupId: " + text(library.groupId()));
        lines.add("- artifactId: " + text(library.artifactId()));
        lines.add("- version: " + text(library.version()));
        lines.add("- coordinates: " + text(library.coordinates()));
        lines.add("- name: " + text(library.name()));
        lines.add("- filename: " + text(library.filename()));
        lines.add("- type: " + text(library.type()));
        lines.add("- sha1: " + text(library.sha1()));
        lines.add("- architecture: " + text(library.architecture()));
        lines.add("- language version: " + text(library.languageVersion()));
        lines.add("- description: " + text(library.description()));
        lines.add("");
    }

    private void appendLocations(List<String> lines, List<FindingLocation> locations) {
        lines.add("Where Mend says it found it:");
        lines.add("");
        if (locations.isEmpty()) {
            lines.add("- " + NOT_PROVIDED);
            lines.add("");
            return;
        }
        for (FindingLocation location : locations) {
            lines.add("- " + text(location.path()) + " (match type: " + text(location.matchType()) + ")");
        }
        lines.add("");
    }

    private void appendRemediation(List<String> lines, Remediation remediation) {
        lines.add("Fixes Mend offered:");
        lines.add("");
        if (!remediation.hasAnyFix()) {
            lines.add("- " + NOT_PROVIDED);
            lines.add("");
            return;
        }
        if (remediation.hasTopFix()) {
            lines.add("Preferred:");
            lines.add("");
            appendFix(lines, remediation.topFix());
        }
        if (!remediation.allFixes().isEmpty()) {
            lines.add("All fixes Mend listed, including alternatives:");
            lines.add("");
            for (RecommendedFix fix : remediation.allFixes()) {
                appendFix(lines, fix);
            }
        }
    }

    private void appendFix(List<String> lines, RecommendedFix fix) {
        lines.add("- type: " + text(fix.type()));
        lines.add("  vulnerability: " + text(fix.vulnerability()));
        lines.add("  origin: " + text(fix.origin()));
        lines.add("  url: " + text(fix.url()));
        lines.add("  resolution: " + text(fix.fixResolution()));
        lines.add("  date: " + text(fix.date()));
        lines.add("  message: " + text(fix.message()));
        lines.add("");
    }

    /** A value as it should appear in a prompt: redacted, or {@code Not provided} when absent. */
    public String text(String value) {
        if (value == null || value.isBlank()) {
            return NOT_PROVIDED;
        }
        return redactor.redact(value);
    }
}
