package com.tungsten.depbot.implementation;

import com.tungsten.depbot.assessment.AnalysisRemediationGroup;
import com.tungsten.depbot.assessment.Assessments;
import com.tungsten.depbot.assessment.FindingAssessment;
import com.tungsten.depbot.remediation.RejectionStage;
import com.tungsten.depbot.validation.FullBuildValidationGate;
import com.tungsten.depbot.validation.RemediationValidationGate;
import com.tungsten.depbot.validation.ValidationOutcome;

import java.nio.file.Path;
import java.util.List;

/**
 * Hand-authored implementation-phase fixtures, built on the shared assessment ones.
 *
 * <p>Public for the same reason {@code Assessments} and {@code GitTestRepos} are: the orchestration test
 * exercises both phases and needs the same documents. Test-support code only.
 */
public final class Implementations {

    public static final String BRANCH = "remediation/run1/critical/org.bouncycastle__bcprov-jdk18on";

    private Implementations() {
    }

    /** A valid {@code COMPLETED} report, with {@code extra} appended as further fields. */
    public static String completedJson(String extra) {
        return """
                {
                  "schemaVersion": "1.0",
                  "coordinates": "org.bouncycastle:bcprov-jdk18on",
                  "conclusion": "COMPLETED",
                  "summary": "raised the bouncycastle property to 1.85 and refreshed the licence list",
                  "observedState": "the root pom pins 1.84 through <bouncycastle.version>, as assessed",
                  "changesMade": ["raised <bouncycastle.version> to 1.85", "regenerated THIRD-PARTY.txt"],
                  "divergenceFromAssessment": [],
                  "validationPerformed": ["dependency:tree resolves 1.85 in every module"],
                  "remainingWork": [],
                  "risks": ["nothing has compiled or tested the result"]%s
                }
                """.formatted(extra == null ? "" : ",\n  " + extra);
    }

    public static String completedJson() {
        return completedJson(null);
    }

    /** The safe stop: the branch disproved the assessment's premise. */
    public static String contradictedJson() {
        return """
                {
                  "schemaVersion": "1.0",
                  "coordinates": "org.bouncycastle:bcprov-jdk18on",
                  "conclusion": "STOPPED_ASSESSMENT_CONTRADICTED",
                  "summary": "stopped: this branch is already on 1.85, so there is nothing to raise",
                  "observedState": "the root pom on this branch pins 1.85, not 1.84",
                  "changesMade": [],
                  "divergenceFromAssessment": [
                    "the assessment observed 1.84; this branch has 1.85",
                    "the recommended target would therefore be a no-op"
                  ],
                  "validationPerformed": ["read the root pom on this branch"],
                  "remainingWork": ["confirm which ref the finding really came from"],
                  "risks": []
                }
                """;
    }

    /** The plan-deviation stop: the approved plan itself turned out to be wrong or incomplete. */
    public static String planDeviationJson() {
        return """
                {
                  "schemaVersion": "1.0",
                  "conclusion": "STOPPED_PLAN_DEVIATION_REQUIRED",
                  "coordinates": "org.bouncycastle:bcprov-jdk18on",
                  "summary": "stopped: the approved plan's target version does not exist",
                  "observedState": "1.85 is not a published release; the nearest fixed release is 1.85.1",
                  "changesMade": [],
                  "divergenceFromAssessment": [],
                  "validationPerformed": ["checked Maven Central for 1.85"],
                  "remainingWork": ["the plan needs to target 1.85.1 instead of 1.85"],
                  "risks": []
                }
                """;
    }

    public static String blockedJson() {
        return """
                {
                  "schemaVersion": "1.0",
                  "conclusion": "STOPPED_BLOCKED",
                  "coordinates": "org.bouncycastle:bcprov-jdk18on",
                  "summary": "stopped: the fixed version is not available to this build",
                  "observedState": "the root pom pins 1.84 through a property, as assessed",
                  "changesMade": [],
                  "divergenceFromAssessment": [],
                  "validationPerformed": [],
                  "remainingWork": ["mirror 1.85 into the internal repository first"],
                  "risks": ["1.85 is not resolvable offline from the configured mirror"]
                }
                """;
    }

    /**
     * A gate that agrees, without running Maven.
     *
     * <p>Used by tests about the surrounding logic. Whether the real gate reaches the right verdict is
     * {@code DependencyResolutionGateTest}'s subject, and running Maven here would make every one of these
     * tests depend on an offline repository being warm.
     */
    public static RemediationValidationGate passingGate() {
        return request -> ValidationOutcome.passed(
                "stub gate: not checked", List.of("stub"), "stub output");
    }

    /** A gate that refuses, so the refusal path can be exercised without breaking a real POM. */
    public static RemediationValidationGate failingGate(String reason) {
        return request -> ValidationOutcome.failed(reason, List.of("stub"), "stub output");
    }

    /** A gate that could not reach a verdict at all. */
    public static RemediationValidationGate inconclusiveGate() {
        return request -> ValidationOutcome.notRun(
                "stub gate: Maven could not be started", List.of("stub"), "");
    }

    /**
     * A full-build gate that passes instantly, without ever running Maven.
     *
     * <p>The default for every test that is not itself about the build gate's own behaviour --
     * {@code MavenBuildValidationGateTest} owns that. Since the full build now runs unconditionally after
     * every commit, every existing test that reaches a commit must supply some full-build gate; this is
     * the one that keeps them exactly as fast and as free of real Maven as they were before this stage
     * existed.
     */
    public static FullBuildValidationGate passingBuildGate() {
        return (request, heartbeat) -> ValidationOutcome.passed(
                "stub full build: not run", List.of("stub"), "stub output");
    }

    /** A full-build gate that reports failure, so the "commit stands, build failed" path can be exercised. */
    public static FullBuildValidationGate failingBuildGate(String reason) {
        return (request, heartbeat) -> ValidationOutcome.failed(reason, List.of("stub"), "stub output");
    }

    public static ImplementationContext context(Path workspace, String baseSha) {
        return context(workspace, baseSha, Assessments.remediationGroup(2), Assessments.remediationRequiredFinding());
    }

    public static ImplementationContext context(Path workspace, String baseSha, AnalysisRemediationGroup group) {
        return context(workspace, baseSha, group, Assessments.remediationRequiredFinding(group.groupId()));
    }

    public static ImplementationContext context(
            Path workspace, String baseSha, AnalysisRemediationGroup group, FindingAssessment findingAssessment) {
        return new ImplementationContext(
                "run1", "critical__org.bouncycastle__bcprov-jdk18on", workspace, BRANCH, baseSha,
                "refs/remotes/origin/release/9.2", group, Assessments.workItem(), findingAssessment);
    }

    /** A hand-authored {@link RepairContext}, for tests of repair-attempt prompt/gate behavior. */
    public static RepairContext repairContext() {
        return new RepairContext(
                "--- a/pom.xml\n+++ b/pom.xml\n@@ -10,1 +10,1 @@\n-<bouncycastle.version>1.84</bouncycastle.version>\n"
                        + "+<bouncycastle.version>1.85</bouncycastle.version>",
                RejectionStage.DEPENDENCY_VALIDATION,
                ValidationOutcome.failed("1.85 does not resolve in module webapp-core",
                        List.of("mvn", "-o", "-B", "dependency:tree"), "stub output"),
                null,
                null,
                null,
                List.of(),
                "the dependency-resolution gate did not pass: 1.85 does not resolve in module webapp-core");
    }

    /** {@link #context(Path, String)}, but as a repair attempt (attempt 2) with a {@link RepairContext} attached. */
    public static ImplementationContext contextWithRepairContext(Path workspace, String baseSha) {
        ImplementationContext base = context(workspace, baseSha);
        return new ImplementationContext(
                base.runId(), base.unitId(), base.workspace(), base.branchName(), base.branchBaseSha(),
                base.verifiedSourceRef(), base.group(), base.members(), base.companionCoordinates(),
                base.priority(), base.executionOrder(), base.partialAnalysisState(), repairContext(), 2);
    }
}
