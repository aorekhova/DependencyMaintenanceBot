package com.tungsten.depbot.assessment;

import com.tungsten.depbot.report.actionable.ActionableFinding;
import com.tungsten.depbot.report.actionable.ActionableReport;
import com.tungsten.depbot.report.actionable.ActionableSummary;
import com.tungsten.depbot.report.actionable.AffectedLibrary;
import com.tungsten.depbot.report.actionable.FindingLocation;
import com.tungsten.depbot.report.actionable.RecommendedFix;
import com.tungsten.depbot.report.actionable.Remediation;

import java.nio.file.Path;
import java.util.List;

/**
 * Hand-authored batch-analysis fixtures. Nothing here is a real Claude answer or a real Mend response --
 * these are synthetic, for the same reason every Mend fixture in this project is.
 *
 * <p>Public so the implementation and orchestration tests can reuse the same fixtures rather than
 * hand-rolling near-identical ones. Test-support code only; never shipped in the production jar.
 *
 * <p>Under the batch analysis model, what used to be one {@code DeveloperAssessment} is now split: a
 * lightweight {@link FindingAssessment} per finding, and a group-level {@link AnalysisRemediationGroup}
 * carrying the plan/automation decision every {@code REMEDIATION_REQUIRED} finding in it shares.
 */
public final class Assessments {

    public static final String DEFAULT_GROUP_ID = "g-bcprov";

    private Assessments() {
    }

    /** The finding half of a complete {@code REMEDIATION_REQUIRED} conclusion, pointing at {@code groupId}. */
    public static FindingAssessment remediationRequiredFinding(String groupId) {
        return new FindingAssessment(
                "org.bouncycastle:bcprov-jdk18on",
                List.of("CVE-2026-58062"),
                "The release branch pins bcprov through a version property; 1.85 closes it forward.",
                AssessmentConclusion.REMEDIATION_REQUIRED,
                groupId,
                List.of("git show origin/release/9.2:pom.xml shows 1.84"),
                List.of("the licence metadata is generated, so it may need regenerating by hand"));
    }

    /** Convenience: the finding half, pointing at {@link #DEFAULT_GROUP_ID}. */
    public static FindingAssessment remediationRequiredFinding() {
        return remediationRequiredFinding(DEFAULT_GROUP_ID);
    }

    /**
     * A complete, valid remediation group scoring {@code impactScore}, judged safe to automate
     * regardless of that score -- {@code impactScore} and {@code automationSafety} are deliberately
     * independent here, exactly as production code must treat them. Use {@link #withAutomationSafety}
     * to build a fixture that needs a different automation-safety verdict.
     */
    public static AnalysisRemediationGroup remediationGroup(String groupId, int impactScore) {
        return new AnalysisRemediationGroup(
                groupId,
                List.of("org.bouncycastle:bcprov-jdk18on"),
                List.of(),
                "a single, unrelated finding",
                "origin/release/9.2",
                "0123456789abcdef0123456789abcdef01234567",
                DependencyOrigin.PROPERTY,
                "declared in the root pom, version taken from <bouncycastle.version>",
                "1.84",
                "raise the version property and refresh the generated licence metadata",
                "1.85",
                List.of("pom.xml"),
                new ImpactScore(impactScore),
                "one property and one generated file, no source changes",
                AutomationSafety.AUTOMATIC_ALLOWED,
                "no coordinated or runtime-sensitive dependency is involved",
                List.of("raise the property to 1.85", "refresh the generated licence list"),
                List.of("run dependency:tree and confirm 1.85 resolves"),
                List.of());
    }

    /** Convenience: {@link #remediationGroup(String, int)} under {@link #DEFAULT_GROUP_ID}. */
    public static AnalysisRemediationGroup remediationGroup(int impactScore) {
        return remediationGroup(DEFAULT_GROUP_ID, impactScore);
    }

    /**
     * The same group with an explicit, real {@code plannedChanges} entry -- a literal {@code VERSION_BUMP}
     * for {@code org.bouncycastle:bcprov-jdk18on} 1.84 -&gt; 1.85 in {@code pom.xml}, which {@code
     * PlanConformanceGate} can confirm from a real {@code <dependency><version>1.85</version></dependency>}
     * declaration. Deliberately opt-in, not the default {@link #remediationGroup(int)} shape: most fixtures
     * across this codebase exercise implementation/prompt/summary behavior that has nothing to do with
     * plan conformance, and edit arbitrary files a narrow {@code plannedChanges} entry would only get in
     * the way of.
     */
    public static AnalysisRemediationGroup withPlannedChanges(
            AnalysisRemediationGroup original, List<PlannedDependencyChange> plannedChanges) {
        return new AnalysisRemediationGroup(
                original.groupId(), original.memberCoordinates(), original.companionCoordinates(),
                original.groupingReason(), original.sourceRef(), original.claimedSourceCommitSha(),
                original.origin(), original.dependencyRelationship(), original.observedVersion(),
                original.recommendedRemediation(), original.recommendedTargetVersion(), original.affectedFiles(),
                original.impactScore(), original.impactReason(), original.automationSafety(),
                original.automationSafetyReason(), original.implementationPlan(), original.validationPlan(),
                plannedChanges);
    }

    /** {@link #remediationGroup(int)} with a real, verifiable VERSION_BUMP plannedChange attached. */
    public static AnalysisRemediationGroup remediationGroupWithPlannedChanges(int impactScore) {
        return withPlannedChanges(remediationGroup(impactScore), List.of(new PlannedDependencyChange(
                "org.bouncycastle:bcprov-jdk18on", "1.84", "1.85", "pom.xml",
                PlannedChangeType.VERSION_BUMP, "raise the version property to 1.85")));
    }

    /** The jackson-databind situation: the artifact is simply not in this repository. */
    public static FindingAssessment noActionRequired() {
        return new FindingAssessment(
                "com.fasterxml.jackson.core:jackson-databind",
                List.of("CVE-2026-59889"),
                "Not present on any ref. The only Jackson here is the legacy org.codehaus lineage.",
                AssessmentConclusion.NO_ACTION_REQUIRED,
                null,
                List.of("no origin/* ref declares it", "dependency:tree is empty for all 12 modules"),
                List.of("if the finding came from a deployed WAR, the jar enters from outside this build"),
                NoActionBasis.DEPENDENCY_NOT_PRESENT);
    }

    public static FindingAssessment inconclusive() {
        return new FindingAssessment(
                "com.mchange:c3p0",
                List.of("CVE-2026-55223"),
                "Declared on two refs, but transitive reach could not be established offline.",
                AssessmentConclusion.INCONCLUSIVE,
                null,
                List.of(),
                List.of("dependency:tree could not run offline, so transitive presence is unconfirmed"));
    }

    /** A required-remediation group that never pinned down a ref -- valid, but not automatable. */
    public static AnalysisRemediationGroup remediationGroupWithoutSourceRef() {
        return withSourceRef(remediationGroup(2), null);
    }

    public static AnalysisRemediationGroup withSourceRef(AnalysisRemediationGroup original, String sourceRef) {
        return new AnalysisRemediationGroup(
                original.groupId(), original.memberCoordinates(), original.companionCoordinates(),
                original.groupingReason(), sourceRef, original.claimedSourceCommitSha(), original.origin(),
                original.dependencyRelationship(), original.observedVersion(), original.recommendedRemediation(),
                original.recommendedTargetVersion(), original.affectedFiles(), original.impactScore(),
                original.impactReason(), original.automationSafety(), original.automationSafetyReason(),
                original.implementationPlan(), original.validationPlan(), original.plannedChanges());
    }

    public static AnalysisRemediationGroup withImpactScore(AnalysisRemediationGroup original, ImpactScore score) {
        return new AnalysisRemediationGroup(
                original.groupId(), original.memberCoordinates(), original.companionCoordinates(),
                original.groupingReason(), original.sourceRef(), original.claimedSourceCommitSha(),
                original.origin(), original.dependencyRelationship(), original.observedVersion(),
                original.recommendedRemediation(), original.recommendedTargetVersion(), original.affectedFiles(),
                score, original.impactReason(), original.automationSafety(), original.automationSafetyReason(),
                original.implementationPlan(), original.validationPlan(), original.plannedChanges());
    }

    /**
     * The same group with a different, explicitly chosen automation-safety verdict and reason -- for
     * tests that demonstrate the verdict is independent of {@code impactScore}.
     */
    public static AnalysisRemediationGroup withAutomationSafety(
            AnalysisRemediationGroup original, AutomationSafety automationSafety, String automationSafetyReason) {
        return new AnalysisRemediationGroup(
                original.groupId(), original.memberCoordinates(), original.companionCoordinates(),
                original.groupingReason(), original.sourceRef(), original.claimedSourceCommitSha(),
                original.origin(), original.dependencyRelationship(), original.observedVersion(),
                original.recommendedRemediation(), original.recommendedTargetVersion(), original.affectedFiles(),
                original.impactScore(), original.impactReason(), automationSafety, automationSafetyReason,
                original.implementationPlan(), original.validationPlan(), original.plannedChanges());
    }

    /** For grouping tests: the same group, but naming companion coordinates with no finding of their own. */
    public static AnalysisRemediationGroup withCompanionCoordinates(
            AnalysisRemediationGroup original, String... companionCoordinates) {
        return new AnalysisRemediationGroup(
                original.groupId(), original.memberCoordinates(), List.of(companionCoordinates),
                original.groupingReason(), original.sourceRef(), original.claimedSourceCommitSha(),
                original.origin(), original.dependencyRelationship(), original.observedVersion(),
                original.recommendedRemediation(), original.recommendedTargetVersion(), original.affectedFiles(),
                original.impactScore(), original.impactReason(), original.automationSafety(),
                original.automationSafetyReason(), original.implementationPlan(), original.validationPlan(),
                original.plannedChanges());
    }

    /** For multi-member group tests: the same group, but naming more member coordinates. */
    public static AnalysisRemediationGroup withMemberCoordinates(
            AnalysisRemediationGroup original, String... memberCoordinates) {
        return new AnalysisRemediationGroup(
                original.groupId(), List.of(memberCoordinates), original.companionCoordinates(),
                original.groupingReason(), original.sourceRef(), original.claimedSourceCommitSha(),
                original.origin(), original.dependencyRelationship(), original.observedVersion(),
                original.recommendedRemediation(), original.recommendedTargetVersion(), original.affectedFiles(),
                original.impactScore(), original.impactReason(), original.automationSafety(),
                original.automationSafetyReason(), original.implementationPlan(), original.validationPlan(),
                original.plannedChanges());
    }

    // ---- documents as Claude would emit them (batch analysis) -----------------------------------

    /** A valid single-finding, single-group batch document, with {@code extra} appended to the group. */
    public static String json(String extra) {
        return """
                {
                  "schemaVersion": "1.0",
                  "findings": [
                    {
                      "coordinates": "org.bouncycastle:bcprov-jdk18on",
                      "vulnerabilityIds": ["CVE-2026-58062"],
                      "summary": "the release branch pins bcprov through a version property",
                      "conclusion": "REMEDIATION_REQUIRED",
                      "remediationGroupId": "g-bcprov",
                      "evidence": ["git show origin/release/9.2:pom.xml shows 1.84"]
                    }
                  ],
                  "remediationGroups": [
                    {
                      "groupId": "g-bcprov",
                      "memberCoordinates": ["org.bouncycastle:bcprov-jdk18on"],
                      "groupingReason": "a single, unrelated finding",
                      "sourceRef": "origin/release/9.2",
                      "sourceCommitSha": "0123456789abcdef0123456789abcdef01234567",
                      "origin": "PROPERTY",
                      "dependencyRelationship": "version taken from <bouncycastle.version>",
                      "observedVersion": "1.84",
                      "recommendedRemediation": "raise the version property to 1.85",
                      "recommendedTargetVersion": "1.85",
                      "affectedFiles": ["pom.xml"],
                      "impactScore": 2,
                      "impactReason": "one property, no source changes",
                      "automationSafety": "AUTOMATIC_ALLOWED",
                      "automationSafetyReason": "no coordinated or runtime-sensitive dependency is involved",
                      "implementationPlan": ["raise the property to 1.85"],
                      "validationPlan": ["run dependency:tree"],
                      "plannedChanges": [
                        {
                          "dependencyCoordinates": "org.bouncycastle:bcprov-jdk18on",
                          "currentVersion": "1.84",
                          "targetVersion": "1.85",
                          "affectedFile": "pom.xml",
                          "changeType": "VERSION_BUMP",
                          "reason": "raises the version property recorded in pom.xml to close the CVE"
                        }
                      ]%s
                    }
                  ]
                }
                """.formatted(extra == null ? "" : ",\n  " + extra);
    }

    public static String json() {
        return json(null);
    }

    /** The same document wrapped in the prose and fenced block a real answer would have. */
    public static String answerContaining(String json) {
        return """
                ## Analysis

                I looked at the refs and the build files and reached the following conclusions.

                ```json
                %s
                ```
                """.formatted(json);
    }

    /** A Claude Code JSON output document whose {@code result} is {@code answerText}. */
    public static String claudeOutput(String answerText) {
        return "{\"is_error\":false,\"subtype\":\"success\",\"type\":\"result\",\"result\":"
                + quote(answerText) + "}";
    }

    private static String quote(String value) {
        StringBuilder quoted = new StringBuilder("\"");
        for (char character : value.toCharArray()) {
            switch (character) {
                case '"' -> quoted.append("\\\"");
                case '\\' -> quoted.append("\\\\");
                case '\n' -> quoted.append("\\n");
                case '\r' -> quoted.append("\\r");
                case '\t' -> quoted.append("\\t");
                default -> quoted.append(character);
            }
        }
        return quoted.append('"').toString();
    }

    // ---- the finding context handed to an assessment ------------------------------------------

    public static AffectedLibrary library(String groupId, String artifactId, String version) {
        return new AffectedLibrary(groupId, artifactId, version,
                groupId + ":" + artifactId + ":" + version, artifactId,
                artifactId + "-" + version + ".jar", "JAVA", "sha1-value", "key-uuid",
                "any", "1.8", "a library description");
    }

    public static ActionableFinding finding(
            String vulnerabilityId, String severity, AffectedLibrary library, String fixResolution) {
        RecommendedFix topFix = new RecommendedFix(vulnerabilityId, "UPGRADE_VERSION", "VENDOR",
                "https://example.invalid/advisory", fixResolution, "2026-01-01", "upgrade it");
        RecommendedFix alternative = new RecommendedFix(vulnerabilityId, "WORKAROUND", "COMMUNITY",
                "https://example.invalid/workaround", "disable the affected feature", "2026-01-02",
                "or turn it off");
        return new ActionableFinding(
                vulnerabilityId, "CVE", severity, "High", "8.1", 8.1d, "8.1",
                "CVSS:3.1/AV:N/AC:L", "a description of " + vulnerabilityId,
                "2026-01-01", "2026-02-01", "https://example.invalid/" + vulnerabilityId,
                "a-product", "a-project", library,
                List.of(new FindingLocation("modules/core/pom.xml", "EXACT_MATCH")),
                new Remediation(topFix, List.of(topFix, alternative)));
    }

    public static ActionableReport reportOf(ActionableFinding... findings) {
        List<ActionableFinding> list = List.of(findings);
        return new ActionableReport("2026-08-04T09:00:00Z", ActionableReport.CURRENT_VERSION,
                new ActionableSummary(list.size(), 0, 0, 0, 0, 0, list.size()), list);
    }

    /** One bcprov work item with two CVEs and a bot-computed suggestion. */
    public static VulnerabilityWorkItem workItem() {
        AffectedLibrary bcprov = library("org.bouncycastle", "bcprov-jdk18on", "1.84");
        return new VulnerabilityWorkItem("org.bouncycastle", "bcprov-jdk18on", "1.84", "CRITICAL", "1.85",
                List.of(
                        finding("CVE-2026-58062", "critical", bcprov,
                                "Upgrade to version org.bouncycastle:bcprov-jdk18on:1.85"),
                        finding("CVE-2026-59650", "high", bcprov,
                                "Upgrade to version org.bouncycastle:bcprov-jdk18on:1.85")));
    }

    public static AnalysisContext context(Path workspace) {
        return new AnalysisContext("run1", workspace, "master", "abc1234def5678", true, List.of(workItem()));
    }

    public static AnalysisContext context(Path workspace, List<VulnerabilityWorkItem> workItems) {
        return new AnalysisContext("run1", workspace, "master", "abc1234def5678", true, workItems);
    }
}
