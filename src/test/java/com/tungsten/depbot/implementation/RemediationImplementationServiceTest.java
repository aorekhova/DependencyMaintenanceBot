package com.tungsten.depbot.implementation;

import com.tungsten.depbot.assessment.Assessments;
import com.tungsten.depbot.claude.ClaudeArtifacts;
import com.tungsten.depbot.claude.ClaudeCodeExecutor;
import com.tungsten.depbot.claude.ClaudeConfig;
import com.tungsten.depbot.claude.ClaudePhase;
import com.tungsten.depbot.claude.ClaudeProcessRunner;
import com.tungsten.depbot.claude.FakeClaude;
import com.tungsten.depbot.git.ChangeDisposition;
import com.tungsten.depbot.git.ChangeOutcome;
import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.git.GitTestRepos;
import com.tungsten.depbot.git.RemediationChangeCommitter;
import com.tungsten.depbot.git.RemediationDiffPolicy;
import com.tungsten.depbot.progress.RemediationProgressListener;
import com.tungsten.depbot.progress.RemediationStep;
import com.tungsten.depbot.report.SecretRedactor;
import com.tungsten.depbot.run.RemediationRunService;
import com.tungsten.depbot.validation.FullBuildValidationGate;
import com.tungsten.depbot.validation.RemediationValidationGate;
import com.tungsten.depbot.validation.ValidationOutcome;
import com.tungsten.depbot.validation.ValidationStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The implementation phase against a real git repository and the real process path: a branch that exists,
 * a fake executable that edits files, and the orchestrator deciding afterwards what to keep.
 */
class RemediationImplementationServiceTest {

    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-08-10T10:00:00Z"), ZoneOffset.UTC);
    private static final String RUN_ID = "run1";
    private static final String UNIT_ID = "critical__org.bouncycastle__bcprov-jdk18on";

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();
    private Path repo;
    private String baseSha;

    @BeforeEach
    void prepareBranch() throws Exception {
        repo = GitTestRepos.createOriginAndSingleBranchClone(tempDir, "release/9.2");
        git.createBranch(repo, Implementations.BRANCH, GitTestRepos.shaOf(repo, "master"));
        git.checkout(repo, Implementations.BRANCH);
        baseSha = git.currentHeadSha(repo);
    }

    private Path runsRoot() {
        return tempDir.resolve("runs");
    }

    private ClaudeConfig config(FakeClaude fake) {
        return new ClaudeConfig(fake.executable().toString(), "opus", 20, Duration.ofSeconds(60));
    }

    /**
     * A config with a deliberately short implementation timeout, to exercise the timeout path without
     * waiting out the real default. {@code implementationTimeout} is what actually governs the
     * implementation call now that it has its own -- the shared {@code timeout} passed to the 4-arg
     * convenience constructor no longer does, so this uses the full constructor to set it directly.
     */
    private ClaudeConfig impatientConfig(FakeClaude fake) {
        return new ClaudeConfig(fake.executable().toString(), "opus", 5,
                ClaudeConfig.DEFAULT_ANALYSIS_MAX_TURNS, ClaudeConfig.DEFAULT_IMPLEMENTATION_MAX_TURNS,
                ClaudeConfig.DEFAULT_HUMAN_REVIEW_MAX_TURNS,
                ClaudeConfig.DEFAULT_ANALYSIS_FINALIZATION_MAX_TURNS,
                ClaudeConfig.DEFAULT_IMPLEMENTATION_FINALIZATION_MAX_TURNS,
                ClaudeConfig.DEFAULT_HUMAN_REVIEW_FINALIZATION_MAX_TURNS,
                Duration.ofSeconds(60), Duration.ofSeconds(ClaudeConfig.DEFAULT_ANALYSIS_TIMEOUT_SECONDS),
                Duration.ofSeconds(1), Duration.ofSeconds(ClaudeConfig.DEFAULT_HUMAN_REVIEW_TIMEOUT_SECONDS),
                ClaudeConfig.DEFAULT_ANALYSIS_SECOND_ATTEMPT_MAX_TURNS,
                Duration.ofSeconds(ClaudeConfig.DEFAULT_ANALYSIS_SECOND_ATTEMPT_TIMEOUT_SECONDS));
    }

    private RemediationImplementationService service(FakeClaude fake) {
        return service(fake, new ImplementationPromptRenderer());
    }

    private RemediationImplementationService service(FakeClaude fake, ImplementationPromptRenderer renderer) {
        return service(fake, renderer, Implementations.passingGate());
    }

    private RemediationImplementationService service(
            FakeClaude fake, ImplementationPromptRenderer renderer, RemediationValidationGate gate) {
        return service(fake, renderer, gate, Implementations.passingBuildGate());
    }

    private RemediationImplementationService service(
            FakeClaude fake, ImplementationPromptRenderer renderer, RemediationValidationGate gate,
            FullBuildValidationGate buildGate) {
        return service(fake, renderer, gate, buildGate, RemediationProgressListener.none());
    }

    private RemediationImplementationService service(
            FakeClaude fake, ImplementationPromptRenderer renderer, RemediationValidationGate gate,
            FullBuildValidationGate buildGate, RemediationProgressListener progress) {
        RemediationRunService runService = new RemediationRunService(FIXED_CLOCK, runsRoot());
        return new RemediationImplementationService(
                new ClaudeCodeExecutor(config(fake), new ClaudeProcessRunner(), runService, FIXED_CLOCK),
                config(fake), runService, renderer, git,
                new RemediationChangeCommitter(git, new RemediationDiffPolicy()), gate, buildGate, progress);
    }

    /** A fake that answers the implementation phase with {@code answer} and optionally edits a file. */
    private FakeClaude fakeAnswering(String answer, String editedFile, String content) throws IOException {
        FakeClaude.Builder builder = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.IMPLEMENTATION, Assessments.claudeOutput(answer));
        if (editedFile != null) {
            builder.creatingFile(editedFile, content);
        }
        return builder.build();
    }

    private Path directory() {
        return runsRoot().resolve(RUN_ID).resolve("units").resolve(UNIT_ID)
                .resolve("implementation").resolve("attempt-1");
    }

    private String artifact(String name) throws IOException {
        Path path = directory().resolve(name);
        return Files.exists(path) ? Files.readString(path, StandardCharsets.UTF_8) : "";
    }

    // ---- a completed remediation is kept ---------------------------------------------------------

    @Test
    @DisplayName("a completed remediation is committed on the branch, with the report persisted")
    void completedRemediationIsCommitted() throws Exception {
        FakeClaude fake = fakeAnswering(
                Assessments.answerContaining(Implementations.completedJson()),
                "pom.xml", "<project><bouncycastle.version>1.85</bouncycastle.version></project>\n");

        ImplementationOutcome outcome = service(fake).implement(Implementations.context(repo, baseSha));

        assertTrue(outcome.hasReport());
        assertTrue(outcome.committed());
        assertEquals(ChangeDisposition.COMMITTED_PENDING_VALIDATION, outcome.disposition());
        assertFalse(baseSha.equals(git.currentHeadSha(repo)), "the branch tip must have moved");
        assertTrue(git.isClean(repo));
        assertTrue(artifact(RemediationImplementationService.REPORT_FILE).contains("COMPLETED"));
        assertTrue(artifact(RemediationImplementationService.PATCH_FILE).contains("1.85"));
    }

    @Test
    @DisplayName("an implementation that commits its own change is still reviewed and re-committed by the "
            + "bot, not bypassed")
    void selfMadeCommitIsReconciledNotBypassed() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.IMPLEMENTATION,
                        Assessments.claudeOutput(Assessments.answerContaining(Implementations.completedJson())))
                .creatingFile("pom.xml", "<project><bouncycastle.version>1.85</bouncycastle.version></project>\n")
                .runningGitCommand(ClaudePhase.IMPLEMENTATION, "add -A")
                .runningGitCommand(ClaudePhase.IMPLEMENTATION, "commit -m selfmadecommit")
                .build();

        ImplementationOutcome outcome = service(fake).implement(Implementations.context(repo, baseSha));

        assertTrue(outcome.committed(),
                "the change must still be committed, even though Claude committed it first: "
                        + outcome.change().reason());
        assertEquals(ChangeDisposition.COMMITTED_PENDING_VALIDATION, outcome.disposition());
        assertNotNull(outcome.validation(),
                "the dependency-resolution gate must still run against the real change, not be skipped "
                        + "because a commit already existed");
        assertTrue(outcome.validation().permitsCommit());

        // Exactly one commit beyond the base -- Claude's own commit was folded into it, not left as a
        // second, separate commit alongside the bot's own.
        String history = GitTestRepos.readOutput(
                repo, "git", "log", "--format=%H %s", baseSha + ".." + Implementations.BRANCH);
        List<String> commitLines = history.lines().filter(line -> !line.isBlank()).toList();
        assertEquals(1, commitLines.size(), "expected exactly one commit beyond the base: " + history);
        assertFalse(commitLines.get(0).contains("selfmadecommit"),
                "Claude's own commit message must not be what ends up on the branch: " + history);
        assertTrue(git.isClean(repo));
    }

    @Test
    @DisplayName("the commit message names the library and carries the report's own summary")
    void commitMessageNamesTheLibraryAndTheReportSummary() throws Exception {
        FakeClaude fake = fakeAnswering(Implementations.completedJson(), "pom.xml", "<project/>\n");

        service(fake).implement(Implementations.context(repo, baseSha));

        String message = GitTestRepos.readOutput(repo, "git", "log", "-1", "--pretty=%B");
        assertTrue(message.contains("org.bouncycastle:bcprov-jdk18on"), message);
        assertTrue(message.contains("1.85"), message);
        assertTrue(message.contains("refreshed the licence list"),
                "the commit should describe what was actually done, not what was predicted: " + message);
    }

    @Test
    @DisplayName("changes far beyond a POM are committed together")
    void changesBeyondAPomAreCommitted() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.IMPLEMENTATION,
                        Assessments.claudeOutput(Implementations.completedJson()))
                .creatingFile("pom.xml", "<project/>\n")
                .creatingFile("src/main/java/com/example/Crypto.java", "class Crypto {}\n")
                .creatingFile("src/test/java/com/example/CryptoTest.java", "class CryptoTest {}\n")
                .creatingFile("src/main/resources/app.properties", "cipher=new\n")
                .creatingFile("THIRD-PARTY.txt", "bcprov 1.85\n")
                .build();

        ImplementationOutcome outcome = service(fake).implement(Implementations.context(repo, baseSha));

        assertTrue(outcome.committed());
        String patch = artifact(RemediationImplementationService.PATCH_FILE);
        assertTrue(patch.contains("Crypto.java"), patch);
        assertTrue(patch.contains("CryptoTest.java"), patch);
        assertTrue(patch.contains("THIRD-PARTY.txt"), patch);
    }

    // ---- a stop is safe --------------------------------------------------------------------------

    @Test
    @DisplayName("a stop on contradicted evidence keeps the report and undoes the partial edits")
    void stopOnContradictionIsSafe() throws Exception {
        FakeClaude fake = fakeAnswering(
                Assessments.answerContaining(Implementations.contradictedJson()),
                "pom.xml", "<project>half-done</project>\n");

        ImplementationOutcome outcome = service(fake).implement(Implementations.context(repo, baseSha));

        assertTrue(outcome.hasReport());
        assertTrue(outcome.stoppedOnContradiction());
        assertFalse(outcome.committed());
        assertEquals(ChangeDisposition.ROLLED_BACK, outcome.disposition());
        assertEquals(baseSha, git.currentHeadSha(repo));
        assertTrue(git.isClean(repo), "the agent was promised it need not revert anything itself");
        assertTrue(artifact(RemediationImplementationService.REPORT_FILE)
                .contains("STOPPED_ASSESSMENT_CONTRADICTED"));
        assertTrue(artifact(RemediationImplementationService.PATCH_FILE).contains("half-done"),
                "the abandoned diff is still the most useful thing to look at");
    }

    @Test
    @DisplayName("a stop that changed nothing is recorded as no change, not as a rollback")
    void stopWithoutEditsIsRecordedAsNoChange() throws Exception {
        FakeClaude fake = fakeAnswering(Implementations.contradictedJson(), null, null);

        ImplementationOutcome outcome = service(fake).implement(Implementations.context(repo, baseSha));

        assertEquals(ChangeDisposition.NO_CHANGES, outcome.disposition());
        assertTrue(outcome.stoppedOnContradiction());
        assertEquals(baseSha, git.currentHeadSha(repo));
    }

    @Test
    @DisplayName("a blocked stop is also not committed")
    void blockedStopIsNotCommitted() throws Exception {
        FakeClaude fake = fakeAnswering(Implementations.blockedJson(), "pom.xml", "<project/>\n");

        ImplementationOutcome outcome = service(fake).implement(Implementations.context(repo, baseSha));

        assertEquals(ImplementationConclusion.STOPPED_BLOCKED, outcome.report().conclusion());
        assertFalse(outcome.committed());
        assertEquals(baseSha, git.currentHeadSha(repo));
    }

    @Test
    @DisplayName("a plan-deviation stop against an approved plan is accepted as a valid outcome, not committed")
    void planDeviationStopIsAcceptedAndNotCommitted() throws Exception {
        FakeClaude fake = fakeAnswering(Implementations.planDeviationJson(), "pom.xml", "<project/>\n");

        ImplementationOutcome outcome = service(fake)
                .implement(Implementations.context(repo, baseSha));

        assertTrue(outcome.hasReport(),
                "an honest STOPPED_PLAN_DEVIATION_REQUIRED report is a usable report, not nothing");
        assertEquals(ImplementationConclusion.STOPPED_PLAN_DEVIATION_REQUIRED, outcome.report().conclusion());
        assertFalse(outcome.committed());
        assertEquals(baseSha, git.currentHeadSha(repo));
        assertTrue(git.isClean(repo));
    }

    // ---- plan conformance (Java-owned, structural, distinct from the self-report above) -----------

    @Test
    @DisplayName("a candidate that conforms to the group's own plan is committed with a conformant verdict recorded")
    void conformantCandidateIsCommittedWithConformanceRecorded() throws Exception {
        FakeClaude fake = fakeAnswering(Implementations.completedJson(), "pom.xml", """
                <project>
                  <dependencies>
                    <dependency>
                      <groupId>org.bouncycastle</groupId>
                      <artifactId>bcprov-jdk18on</artifactId>
                      <version>1.85</version>
                    </dependency>
                  </dependencies>
                </project>
                """);

        ImplementationOutcome outcome = service(fake).implement(
                Implementations.context(repo, baseSha, Assessments.remediationGroupWithPlannedChanges(2)));

        assertTrue(outcome.committed());
        assertNotNull(outcome.planConformance(), "every ordinary attempt has a plan to conform to");
        assertTrue(outcome.planConformance().conformant(), outcome.planConformance().violations().toString());
    }

    @Test
    @DisplayName("a Phase A conformance violation (unauthorized file) skips dependency validation and the "
            + "full build entirely, and refuses the commit")
    void phaseAViolationSkipsDependencyValidationAndFullBuild() throws Exception {
        FakeClaude fake = fakeAnswering(
                Implementations.completedJson(), "unauthorized-file.txt", "not part of the approved plan\n");

        ImplementationOutcome outcome = service(fake)
                .implement(Implementations.context(repo, baseSha, Assessments.remediationGroupWithPlannedChanges(2)));

        assertNotNull(outcome.planConformance());
        assertFalse(outcome.planConformance().conformant());
        assertTrue(outcome.planConformance().violations().stream().anyMatch(v -> v.contains("unauthorized-file.txt")));
        assertNull(outcome.validation(), "dependency validation must never have been invoked at all");
        assertNull(outcome.fullBuildValidation(), "the full build must never run on a plan-deviating candidate");
        assertFalse(outcome.committed(), "a Phase A conformance violation must refuse the commit");
        assertEquals(baseSha, git.currentHeadSha(repo));
    }

    @Test
    @DisplayName("a Phase B conformance violation (resolved version mismatch) skips only the full build -- "
            + "dependency validation itself already ran and genuinely passed")
    void phaseBViolationSkipsOnlyFullBuild() throws Exception {
        // The group's own plannedChanges plans a property-based VERSION_BUMP for
        // org.bouncycastle:bcprov-jdk18on to 1.85. The property is deliberately left undefined anywhere
        // this repository's own POM files can prove -- Phase A cannot resolve it locally and defers to
        // Phase B, which is fed (via this stub gate) a resolution that does not match the plan, so Phase B
        // must flag it. (A property genuinely defined in the same file, as in
        // PlanConformanceGateTest#propertyBasedVersionResolvedDirectlyByPhaseA, is now resolved directly by
        // Phase A itself -- this test exercises the case Phase A genuinely cannot prove on its own.)
        RemediationValidationGate mismatchingResolutionGate = request -> ValidationOutcome.passed(
                "stub gate: resolves, but not to the planned version", List.of("stub"), "stub output", "1.0.9");
        FakeClaude fake = fakeAnswering(Implementations.completedJson(), "pom.xml", """
                <project>
                  <dependencies>
                    <dependency>
                      <groupId>org.bouncycastle</groupId>
                      <artifactId>bcprov-jdk18on</artifactId>
                      <version>${bouncycastle.version}</version>
                    </dependency>
                  </dependencies>
                </project>
                """);

        ImplementationOutcome outcome = service(fake, new ImplementationPromptRenderer(), mismatchingResolutionGate)
                .implement(Implementations.context(repo, baseSha, Assessments.remediationGroupWithPlannedChanges(2)));

        assertNotNull(outcome.planConformance());
        assertFalse(outcome.planConformance().conformant());
        assertTrue(outcome.planConformance().violations().stream().anyMatch(v -> v.contains("1.0.9")));
        assertNotNull(outcome.validation(), "dependency validation must have actually run this time");
        assertEquals(ValidationStatus.PASSED, outcome.validation().status(),
                "dependency validation genuinely passed -- it is a SEPARATE gate that refused the commit");
        assertNull(outcome.fullBuildValidation(), "the full build must never run once conformance failed");
        assertFalse(outcome.committed(), "a Phase B conformance violation must refuse the commit");
        assertEquals(baseSha, git.currentHeadSha(repo));
    }

    // ---- nothing unusable is ever kept -----------------------------------------------------------

    @Test
    @DisplayName("edits with no readable report are rolled back, however good they look")
    void editsWithoutAReadableReportAreRolledBack() throws Exception {
        FakeClaude fake = fakeAnswering("I raised the version. Trust me.",
                "pom.xml", "<project><bouncycastle.version>1.85</bouncycastle.version></project>\n");

        ImplementationOutcome outcome = service(fake).implement(Implementations.context(repo, baseSha));

        assertFalse(outcome.hasReport());
        assertEquals(ChangeDisposition.ROLLED_BACK, outcome.disposition());
        assertEquals(baseSha, git.currentHeadSha(repo));
        assertEquals("", artifact(RemediationImplementationService.REPORT_FILE),
                "no report file may exist when there is no valid report");
    }

    @Test
    @DisplayName("a non-zero exit rolls the work back even when the report would have parsed")
    void nonZeroExitRollsBack() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.IMPLEMENTATION,
                        Assessments.claudeOutput(Implementations.completedJson()), 2)
                .creatingFile("pom.xml", "<project/>\n")
                .build();

        ImplementationOutcome outcome = service(fake).implement(Implementations.context(repo, baseSha));

        assertFalse(outcome.hasReport());
        assertEquals(ChangeDisposition.ROLLED_BACK, outcome.disposition());
        assertEquals(baseSha, git.currentHeadSha(repo));
    }

    @Test
    @DisplayName("a timeout attempts a fresh, read-only finalization before rolling back")
    void timeoutAttemptsFinalizationBeforeRollingBack() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir)
                .creatingFile("pom.xml", "<project/>\n")
                .sleepingFor(30)
                .build();
        RemediationRunService runService = new RemediationRunService(FIXED_CLOCK, runsRoot());
        ClaudeConfig impatient = impatientConfig(fake);
        RemediationImplementationService service = new RemediationImplementationService(
                new ClaudeCodeExecutor(impatient, new ClaudeProcessRunner(), runService, FIXED_CLOCK),
                impatient, runService, new ImplementationPromptRenderer(), git,
                new RemediationChangeCommitter(git, new RemediationDiffPolicy()),
                Implementations.passingGate(), Implementations.passingBuildGate());

        ImplementationOutcome outcome = service.implement(Implementations.context(repo, baseSha));

        assertFalse(outcome.hasReport(),
                "the fake's unscripted default response is not a valid implementation report either");
        assertEquals(ChangeDisposition.ROLLED_BACK, outcome.disposition());
        assertEquals(baseSha, git.currentHeadSha(repo));
        assertTrue(git.isClean(repo));
        assertEquals(List.of("implementation-finalization"), fake.recordedPhaseSequence(),
                "the primary call was killed before it ever reached its own phase branch");
        assertTrue(artifact(RemediationImplementationService.ATTEMPT_FILE)
                .contains("\"finalizationUsed\" : true"));
    }

    // ---- running out of turns or time gets a report-only finalization, not an instant rollback -----

    @Test
    @DisplayName("hitting the turn limit resumes the same session for a short, read-only finalization "
            + "call, and a genuinely finished remediation is still committed")
    void maxTurnsResumesSessionAndCommitsAGenuinelyFinishedRemediation() throws Exception {
        String primaryResponse =
                "{\"is_error\":true,\"subtype\":\"error_max_turns\",\"session_id\":\"sess-impl-1234\"}";
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.IMPLEMENTATION, primaryResponse)
                .creatingFile(ClaudePhase.IMPLEMENTATION, "pom.xml",
                        "<project><bouncycastle.version>1.85</bouncycastle.version></project>\n")
                .respondingToImplementationFinalization(
                        Assessments.claudeOutput(Implementations.completedJson()))
                .build();

        ImplementationOutcome outcome = service(fake).implement(Implementations.context(repo, baseSha));

        assertTrue(outcome.hasReport());
        assertEquals(ImplementationConclusion.COMPLETED, outcome.report().conclusion());
        assertTrue(outcome.committed());
        assertEquals(ChangeDisposition.COMMITTED_PENDING_VALIDATION, outcome.disposition());
        assertEquals(2, fake.invocationCount(), "the primary call and the finalization call");
        assertEquals(List.of("implementation", "implementation-finalization"), fake.recordedPhaseSequence());
        assertTrue(fake.recordedArgs().contains("--resume sess-impl-1234"), fake.recordedArgs());
        assertTrue(artifact(RemediationImplementationService.ATTEMPT_FILE)
                .contains("\"finalizationUsed\" : true"));
        assertTrue(Files.exists(directory().resolve("finalization").resolve(ClaudeArtifacts.STDOUT_FILE)));
        assertTrue(Files.exists(directory().resolve(ClaudeArtifacts.STDOUT_FILE)),
                "the primary call's own artifacts must survive, never overwritten by the finalization call");
    }

    @Test
    @DisplayName("a timeout with no session to resume still gets a fresh, read-only finalization attempt, "
            + "and an honestly incomplete remediation is rolled back, not silently discarded")
    void timeoutWithNoSessionStillGetsAFreshFinalizationAttempt() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir)
                .creatingFile("pom.xml", "<project><bouncycastle.version>1.85</bouncycastle.version></project>\n")
                .sleepingFor(30)
                .respondingToImplementationFinalization(
                        Assessments.claudeOutput(Implementations.blockedJson()))
                .build();
        RemediationRunService runService = new RemediationRunService(FIXED_CLOCK, runsRoot());
        ClaudeConfig impatient = impatientConfig(fake);
        RemediationImplementationService service = new RemediationImplementationService(
                new ClaudeCodeExecutor(impatient, new ClaudeProcessRunner(), runService, FIXED_CLOCK),
                impatient, runService, new ImplementationPromptRenderer(), git,
                new RemediationChangeCommitter(git, new RemediationDiffPolicy()),
                Implementations.passingGate(), Implementations.passingBuildGate());

        ImplementationOutcome outcome = service.implement(Implementations.context(repo, baseSha));

        assertTrue(outcome.hasReport(), "an honest STOPPED_BLOCKED report is a usable report, not nothing");
        assertEquals(ImplementationConclusion.STOPPED_BLOCKED, outcome.report().conclusion());
        assertFalse(outcome.committed());
        assertEquals(baseSha, git.currentHeadSha(repo));
        assertTrue(git.isClean(repo));
        assertFalse(fake.recordedArgs().contains("--resume"),
                "there is no session id to resume after a raw timeout, so this must be a fresh call");
        assertEquals(List.of("implementation-finalization"), fake.recordedPhaseSequence());
    }

    @Test
    @DisplayName("when the finalization attempt also fails, the whole implementation rolls back, naming why")
    void finalizationFailureAlsoRollsBack() throws Exception {
        String primaryResponse =
                "{\"is_error\":true,\"subtype\":\"error_max_turns\",\"session_id\":\"sess-impl-2\"}";
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.IMPLEMENTATION, primaryResponse)
                .creatingFile(ClaudePhase.IMPLEMENTATION, "pom.xml", "<project/>\n")
                .respondingToImplementationFinalization("not a JSON document at all", 1)
                .build();

        ImplementationOutcome outcome = service(fake).implement(Implementations.context(repo, baseSha));

        assertFalse(outcome.hasReport());
        assertEquals(ChangeDisposition.ROLLED_BACK, outcome.disposition());
        assertEquals(baseSha, git.currentHeadSha(repo));
        assertTrue(outcome.failureReason().contains("ran out of turns"), outcome.failureReason());
        assertTrue(outcome.failureReason().contains("finalization"), outcome.failureReason());
        assertTrue(artifact(RemediationImplementationService.ATTEMPT_FILE)
                .contains("\"finalizationUsed\" : true"));
    }

    // ---- finalization is not limited to timeout/max-turns -------------------------------------------

    @Test
    @DisplayName("an ordinary clean end_turn with no usable report still gets a report-only finalization "
            + "attempt, not an immediate rollback")
    void cleanEndTurnWithoutAUsableReportStillGetsFinalization() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.IMPLEMENTATION,
                        Assessments.claudeOutput("I raised the version. Trust me."))
                .creatingFile(ClaudePhase.IMPLEMENTATION, "pom.xml",
                        "<project><bouncycastle.version>1.85</bouncycastle.version></project>\n")
                .respondingToImplementationFinalization(Assessments.claudeOutput(Implementations.blockedJson()))
                .build();

        ImplementationOutcome outcome = service(fake).implement(Implementations.context(repo, baseSha));

        assertTrue(outcome.hasReport(),
                "the primary call ended cleanly with prose instead of JSON -- exactly the shape a real "
                        + "pilot hit -- and finalization must still be attempted for it");
        assertEquals(ImplementationConclusion.STOPPED_BLOCKED, outcome.report().conclusion());
        assertFalse(outcome.committed());
        assertEquals(2, fake.invocationCount(), "the primary call and the finalization call");
        assertEquals(List.of("implementation", "implementation-finalization"), fake.recordedPhaseSequence());
        assertFalse(fake.recordedArgs().contains("--resume"),
                "the primary call's envelope carried no session id, so this must be a fresh call");
        assertTrue(artifact(RemediationImplementationService.ATTEMPT_FILE)
                .contains("\"finalizationUsed\" : true"));
    }

    @Test
    @DisplayName("a self-reported error result also gets a report-only finalization attempt")
    void selfReportedErrorResultStillGetsFinalization() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.IMPLEMENTATION,
                        "{\"is_error\":true,\"subtype\":\"error_during_execution\",\"result\":\"something went wrong\"}")
                .creatingFile(ClaudePhase.IMPLEMENTATION, "pom.xml", "<project/>\n")
                .respondingToImplementationFinalization(Assessments.claudeOutput(Implementations.completedJson()))
                .build();

        ImplementationOutcome outcome = service(fake).implement(Implementations.context(repo, baseSha));

        assertTrue(outcome.hasReport());
        assertTrue(outcome.committed());
        assertEquals(List.of("implementation", "implementation-finalization"), fake.recordedPhaseSequence());
    }

    @Test
    @DisplayName("if even finalization cannot rescue a self-reported error, the failure reason describes "
            + "what actually happened, not a false claim about running out of turns or time")
    void finalizationFailureAfterSelfReportedErrorNamesTheRealReason() throws Exception {
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.IMPLEMENTATION,
                        "{\"is_error\":true,\"subtype\":\"error_during_execution\",\"result\":\"something went wrong\"}")
                .creatingFile(ClaudePhase.IMPLEMENTATION, "pom.xml", "<project/>\n")
                .respondingToImplementationFinalization("not a JSON document at all", 1)
                .build();

        ImplementationOutcome outcome = service(fake).implement(Implementations.context(repo, baseSha));

        assertFalse(outcome.hasReport());
        assertEquals(ChangeDisposition.ROLLED_BACK, outcome.disposition());
        assertTrue(outcome.failureReason().contains("error_during_execution"), outcome.failureReason());
        assertFalse(outcome.failureReason().contains("ran out of turns"), outcome.failureReason());
    }

    // ---- a grouped commit message uses each member's own target version -----------------------------

    /** Builds two independent work items/findings for a c3p0 + mchange-commons-java style group. */
    private static com.tungsten.depbot.assessment.VulnerabilityWorkItem c3p0WorkItem(String mendSuggestedTarget) {
        return new com.tungsten.depbot.assessment.VulnerabilityWorkItem(
                "com.mchange", "c3p0", "0.13.0", "high", mendSuggestedTarget, List.of());
    }

    private static com.tungsten.depbot.assessment.VulnerabilityWorkItem mchangeCommonsWorkItem(
            String mendSuggestedTarget) {
        return new com.tungsten.depbot.assessment.VulnerabilityWorkItem(
                "com.mchange", "mchange-commons-java", "0.5.0", "high", mendSuggestedTarget, List.of());
    }

    private static com.tungsten.depbot.assessment.FindingAssessment mchangeGroupFinding(String coordinates) {
        return new com.tungsten.depbot.assessment.FindingAssessment(
                coordinates, List.of("CVE-X"), "summary",
                com.tungsten.depbot.assessment.AssessmentConclusion.REMEDIATION_REQUIRED, "g-mchange",
                List.of("evidence"), List.of());
    }

    @Test
    @DisplayName("a grouped commit's message uses each member's own Mend-suggested target version, not one "
            + "shared value repeated for every coordinate, when no actual resolved version is available")
    void groupedCommitMessageUsesEachMembersOwnTargetVersion() throws Exception {
        FakeClaude fake = fakeAnswering(Implementations.completedJson(), "pom.xml",
                "<project><c3p0.version>0.14.0</c3p0.version><mchange.version>0.6.0</mchange.version></project>\n");

        com.tungsten.depbot.assessment.VulnerabilityWorkItem c3p0 = c3p0WorkItem("0.14.0");
        com.tungsten.depbot.assessment.VulnerabilityWorkItem mchangeCommons = mchangeCommonsWorkItem("0.6.0");
        // The group's own shared recommendation is deliberately a different value from either member's
        // own target -- proving the per-member value wins, not merely happening to match by coincidence.
        com.tungsten.depbot.assessment.AnalysisRemediationGroup group =
                Assessments.remediationGroup("g-mchange", 2);

        ImplementationContext context = new ImplementationContext(
                RUN_ID, "high__group__g-mchange", repo, Implementations.BRANCH, baseSha,
                "refs/remotes/origin/release/9.2", group,
                List.of(new ImplementationGroupMember(c3p0, mchangeGroupFinding("com.mchange:c3p0")),
                        new ImplementationGroupMember(
                                mchangeCommons, mchangeGroupFinding("com.mchange:mchange-commons-java"))),
                List.of());

        // The stub validation gate used by service(fake) here (Implementations.passingGate()) reports no
        // resolvedVersion at all, exactly like a gate that was never consulted or reached no verdict --
        // so this exercises the fallback to each member's own Mend-suggested target.
        ImplementationOutcome outcome = service(fake).implement(context);

        assertTrue(outcome.committed());
        String subject = GitTestRepos.readOutput(repo, "git", "log", "-1", "--format=%s", Implementations.BRANCH);
        assertTrue(subject.contains("com.mchange:c3p0 -> 0.14.0"), subject);
        assertTrue(subject.contains("com.mchange:mchange-commons-java -> 0.6.0"), subject);
        assertFalse(subject.contains("mchange-commons-java -> 1.85"), subject);
    }

    @Test
    @DisplayName("when the dependency-resolution gate establishes an actual resolved version, the commit "
            + "message uses that instead of Mend's own pre-implementation suggestion")
    void commitMessageUsesTheActualResolvedVersionOverMendsSuggestion() throws Exception {
        FakeClaude fake = fakeAnswering(Implementations.completedJson(), "pom.xml",
                "<project><c3p0.version>0.14.1</c3p0.version><mchange.version>0.6.1</mchange.version></project>\n");

        // Mend originally suggested 0.14.0/0.6.0 -- the Remediation Engineer applied later patch versions
        // instead, for a reason the gate has no opinion on, and the gate's own validated tree confirms
        // 0.14.1/0.6.1 are what is actually there now. The commit title must reflect that reality, not
        // the pre-implementation suggestion.
        com.tungsten.depbot.assessment.VulnerabilityWorkItem c3p0 = c3p0WorkItem("0.14.0");
        com.tungsten.depbot.assessment.VulnerabilityWorkItem mchangeCommons = mchangeCommonsWorkItem("0.6.0");
        com.tungsten.depbot.assessment.AnalysisRemediationGroup group =
                Assessments.remediationGroup("g-mchange", 2);

        ImplementationContext context = new ImplementationContext(
                RUN_ID, "high__group__g-mchange", repo, Implementations.BRANCH, baseSha,
                "refs/remotes/origin/release/9.2", group,
                List.of(new ImplementationGroupMember(c3p0, mchangeGroupFinding("com.mchange:c3p0")),
                        new ImplementationGroupMember(
                                mchangeCommons, mchangeGroupFinding("com.mchange:mchange-commons-java"))),
                List.of());

        RemediationValidationGate gateReportingActualVersions = request -> {
            String actual = "c3p0".equals(request.artifactId()) ? "0.14.1" : "0.6.1";
            return ValidationOutcome.passed(
                    request.coordinates() + " now resolves to " + actual, List.of("stub"), "stub output", actual);
        };

        ImplementationOutcome outcome =
                service(fake, new ImplementationPromptRenderer(), gateReportingActualVersions).implement(context);

        assertTrue(outcome.committed());
        String subject = GitTestRepos.readOutput(repo, "git", "log", "-1", "--format=%s", Implementations.BRANCH);
        assertTrue(subject.contains("com.mchange:c3p0 -> 0.14.1"), subject);
        assertTrue(subject.contains("com.mchange:mchange-commons-java -> 0.6.1"), subject);
        assertFalse(subject.contains("-> 0.14.0"), subject);
        assertFalse(subject.contains("-> 0.6.0"), subject);
    }

    @Test
    @DisplayName("a multi-member group's dependency-resolution gate call uses each member's own reported "
            + "version, never the group's single, shared observedVersion broadcast onto every member")
    void multiMemberGroupUsesEachMembersOwnReportedVersionNotTheGroupsSharedObservedVersion() throws Exception {
        FakeClaude fake = fakeAnswering(Implementations.completedJson(), "pom.xml",
                "<project><c3p0.version>0.14.0</c3p0.version><mchange.version>0.6.0</mchange.version></project>\n");

        com.tungsten.depbot.assessment.VulnerabilityWorkItem c3p0 = c3p0WorkItem("0.14.0");
        com.tungsten.depbot.assessment.VulnerabilityWorkItem mchangeCommons = mchangeCommonsWorkItem("0.6.0");
        // remediationGroup's own observedVersion is a fixed "1.84" (a bcprov-style fixture value) --
        // deliberately unrelated to either member's real reportedVersion (0.13.0/0.5.0), so a wrongly
        // broadcast group-level value would be unmistakable in the captured requests below.
        com.tungsten.depbot.assessment.AnalysisRemediationGroup group =
                Assessments.remediationGroup("g-mchange", 2);
        assertEquals("1.84", group.observedVersion());

        ImplementationContext context = new ImplementationContext(
                RUN_ID, "high__group__g-mchange", repo, Implementations.BRANCH, baseSha,
                "refs/remotes/origin/release/9.2", group,
                List.of(new ImplementationGroupMember(c3p0, mchangeGroupFinding("com.mchange:c3p0")),
                        new ImplementationGroupMember(
                                mchangeCommons, mchangeGroupFinding("com.mchange:mchange-commons-java"))),
                List.of());

        java.util.Map<String, String> vulnerableVersionByArtifact = new java.util.LinkedHashMap<>();
        RemediationValidationGate capturingGate = request -> {
            vulnerableVersionByArtifact.put(request.artifactId(), request.vulnerableVersion());
            return ValidationOutcome.passed(request.coordinates() + " now resolves", List.of("stub"), "stub output");
        };

        ImplementationOutcome outcome =
                service(fake, new ImplementationPromptRenderer(), capturingGate).implement(context);

        assertTrue(outcome.committed());
        assertEquals("0.13.0", vulnerableVersionByArtifact.get("c3p0"),
                "c3p0's own reported version must be used, not the group's shared observedVersion");
        assertEquals("0.5.0", vulnerableVersionByArtifact.get("mchange-commons-java"),
                "mchange-commons-java's own reported version must be used, not the group's shared "
                        + "observedVersion (which belongs to a different member entirely)");
    }

    @Test
    @DisplayName("a singleton group's dependency-resolution gate call still uses the group's own "
            + "observedVersion, when the analysis provided one, since there is only one member it can belong to")
    void singletonGroupStillUsesTheGroupsOwnObservedVersion() throws Exception {
        FakeClaude fake = fakeAnswering(Implementations.completedJson(),
                "pom.xml", "<project><bouncycastle.version>1.85</bouncycastle.version></project>\n");

        java.util.List<String> capturedVulnerableVersions = new ArrayList<>();
        RemediationValidationGate capturingGate = request -> {
            capturedVulnerableVersions.add(request.vulnerableVersion());
            return ValidationOutcome.passed(request.coordinates() + " now resolves", List.of("stub"), "stub output");
        };

        ImplementationOutcome outcome =
                service(fake, new ImplementationPromptRenderer(), capturingGate)
                        .implement(Implementations.context(repo, baseSha));

        assertTrue(outcome.committed());
        assertEquals(List.of("1.84"), capturedVulnerableVersions,
                "a singleton group's own observedVersion (\"1.84\") is unambiguous and must still be used");
    }

    @Test
    @DisplayName("a completed report whose diff trips the policy is still rolled back")
    void policyStillAppliesToACompletedReport() throws Exception {
        FakeClaude fake = fakeAnswering(Implementations.completedJson(),
                "pom.xml", "<project><maven.test.skip>true</maven.test.skip></project>\n");

        ImplementationOutcome outcome = service(fake).implement(Implementations.context(repo, baseSha));

        assertTrue(outcome.hasReport());
        assertEquals(ChangeDisposition.ROLLED_BACK, outcome.disposition());
        assertFalse(outcome.change().policyViolations().isEmpty());
        assertEquals(baseSha, git.currentHeadSha(repo));
    }

    // ---- the call itself -------------------------------------------------------------------------

    @Test
    @DisplayName("the implementation call may edit files and use local git freely, but may not publish anything")
    void callMayEditAndUseLocalGitButMayNotPublish() throws Exception {
        FakeClaude fake = fakeAnswering(Implementations.completedJson(), "pom.xml", "<project/>\n");

        service(fake).implement(Implementations.context(repo, baseSha));

        String args = fake.recordedArgs();
        String allowed = args.substring(0, args.indexOf("--disallowedTools"));
        String disallowed = args.substring(args.indexOf("--disallowedTools"));

        assertTrue(allowed.contains("Write"), args);
        assertTrue(allowed.contains("Edit"), args);
        assertTrue(allowed.contains("Bash"), "local git reaches Claude through the bare Bash entry: " + args);
        assertTrue(disallowed.contains("Bash(git push:*)"), "push must be refused: " + args);
        assertFalse(disallowed.contains("Bash(git fetch:*)"), "fetch must not be refused: " + args);
        assertFalse(disallowed.contains("Bash(git remote:*)"), "remote must not be refused: " + args);
        assertFalse(args.toLowerCase(java.util.Locale.ROOT).contains("dangerously"), args);
    }

    @Test
    @DisplayName("the finding, the assessment and the branch all reach Claude")
    void fullContextReachesClaude() throws Exception {
        FakeClaude fake = fakeAnswering(Implementations.completedJson(), "pom.xml", "<project/>\n");

        service(fake).implement(Implementations.context(repo, baseSha));

        String delivered = fake.recordedStdin();
        assertTrue(delivered.contains("CVE-2026-58062"), delivered);
        assertTrue(delivered.contains("raise the property to 1.85"), delivered);
        assertTrue(delivered.contains(Implementations.BRANCH), delivered);
        assertTrue(delivered.contains(baseSha), delivered);
    }

    @Test
    @DisplayName("Claude runs on the remediation branch, in the repository")
    void claudeRunsOnTheRemediationBranch() throws Exception {
        FakeClaude fake = fakeAnswering(Implementations.completedJson(), "pom.xml", "<project/>\n");

        service(fake).implement(Implementations.context(repo, baseSha));

        assertEquals(List.of(Implementations.BRANCH), fake.recordedBranchSequence());
        assertEquals(Path.of(fake.recordedWorkingDirectory()).toRealPath(), repo.toRealPath());
    }

    @Test
    @DisplayName("exactly one call is made, and it is the implementation")
    void exactlyOneImplementationCallIsMade() throws Exception {
        FakeClaude fake = fakeAnswering(Implementations.completedJson(), "pom.xml", "<project/>\n");

        service(fake).implement(Implementations.context(repo, baseSha));

        assertEquals(1, fake.invocationCount());
        assertEquals(List.of("implementation"), fake.recordedPhaseSequence());
    }

    @Test
    @DisplayName("every path records the attempt, with the branch, its base and the disposition")
    void everyPathRecordsTheAttempt() throws Exception {
        FakeClaude fake = fakeAnswering("no report here", "pom.xml", "<project/>\n");

        service(fake).implement(Implementations.context(repo, baseSha));

        String attempt = artifact(RemediationImplementationService.ATTEMPT_FILE);
        assertTrue(attempt.contains(Implementations.BRANCH), attempt);
        assertTrue(attempt.contains(baseSha), attempt);
        assertTrue(attempt.contains("refs/remotes/origin/release/9.2"), attempt);
        assertTrue(attempt.contains("ROLLED_BACK"), attempt);
        assertTrue(attempt.contains("\"reportUsable\" : false"), attempt);
        assertTrue(attempt.contains("--disallowedTools"), attempt);
    }

    @Test
    @DisplayName("artifacts land under the unit's implementation directory, apart from the assessment's")
    void artifactsLandInTheirOwnDirectory() throws Exception {
        FakeClaude fake = fakeAnswering(Implementations.completedJson(), "pom.xml", "<project/>\n");
        RemediationImplementationService service = service(fake);

        service.implement(Implementations.context(repo, baseSha));

        assertEquals(directory(), service.implementationDirectoryFor(RUN_ID, UNIT_ID, 1));
        assertTrue(Files.exists(directory().resolve(ClaudeArtifacts.PROMPT_FILE)));
        assertTrue(Files.exists(directory().resolve(ClaudeArtifacts.STDOUT_FILE)));
        assertNotNull(artifact(RemediationImplementationService.ATTEMPT_FILE));
    }

    @Test
    @DisplayName("a known credential never reaches the prompt on disk or the process")
    void credentialsNeverReachThePromptOrTheProcess() throws Exception {
        String credential = "mend-user-key-abcdef123456";
        FakeClaude fake = fakeAnswering(Implementations.completedJson(), "pom.xml", "<project/>\n");
        var item = new com.tungsten.depbot.assessment.VulnerabilityWorkItem(
                "g", "a", "1.0", "HIGH", "2.0",
                List.of(Assessments.finding("CVE-X", "high",
                        Assessments.library("g", "a", "1.0"), "token " + credential)));
        ImplementationContext context = new ImplementationContext(RUN_ID, UNIT_ID, repo,
                Implementations.BRANCH, baseSha, "refs/remotes/origin/master", Assessments.remediationGroup(2),
                item, Assessments.remediationRequiredFinding());

        service(fake, new ImplementationPromptRenderer(SecretRedactor.of(credential))).implement(context);

        assertFalse(artifact(ClaudeArtifacts.PROMPT_FILE).contains(credential));
        assertFalse(fake.recordedStdin().contains(credential));
        assertFalse(artifact(RemediationImplementationService.ATTEMPT_FILE).contains(credential));
    }

    @Test
    @DisplayName("nothing is ever pushed: the origin is untouched by an implementation")
    void nothingIsEverPushed() throws Exception {
        Path origin = tempDir.resolve("origin.git");
        String originRefsBefore = GitTestRepos.readOutput(origin, "git", "for-each-ref", "--format=%(refname)");
        FakeClaude fake = fakeAnswering(Implementations.completedJson(), "pom.xml", "<project/>\n");

        service(fake).implement(Implementations.context(repo, baseSha));

        assertEquals(originRefsBefore,
                GitTestRepos.readOutput(origin, "git", "for-each-ref", "--format=%(refname)"),
                "the remediation branch must exist only locally");
    }

    // ---- the full build gate, always run after a real commit --------------------------------------

    @Test
    @DisplayName("the full build runs only after a real commit, and its artifacts are written")
    void fullBuildRunsOnlyAfterACommit() throws Exception {
        FakeClaude fake = fakeAnswering(
                Assessments.answerContaining(Implementations.completedJson()),
                "pom.xml", "<project><bouncycastle.version>1.85</bouncycastle.version></project>\n");

        ImplementationOutcome outcome = implementWith(fake,
                Implementations.passingGate(), Implementations.passingBuildGate());

        assertTrue(outcome.committed());
        assertTrue(outcome.fullBuildRan());
        assertTrue(outcome.fullyBuildValidated());
        assertTrue(artifact(RemediationImplementationService.FULL_BUILD_VALIDATION_FILE).contains("PASSED"));
        assertEquals("stub output", artifact(RemediationImplementationService.FULL_BUILD_OUTPUT_FILE));

        // Bug 6 regression (pilot 20260909-012226-8bfda1): the attempt's own dispositionReason must
        // reflect that the full build already ran and passed, never the stale commit-time-only sentence.
        String attempt = artifact(RemediationImplementationService.ATTEMPT_FILE);
        assertFalse(attempt.contains("nothing has compiled or tested"), attempt);
        assertTrue(attempt.contains("successfully passed dependency validation and full build validation"),
                attempt);
    }

    @Test
    @DisplayName("a failing full build does not undo the commit -- it is kept for diagnosis")
    void fullBuildFailureDoesNotUndoTheCommit() throws Exception {
        FakeClaude fake = fakeAnswering(
                Assessments.answerContaining(Implementations.completedJson()),
                "pom.xml", "<project><bouncycastle.version>1.85</bouncycastle.version></project>\n");

        ImplementationOutcome outcome = implementWith(fake,
                Implementations.passingGate(), Implementations.failingBuildGate("tests failed in module x"));

        assertTrue(outcome.committed(), "the commit already happened before this gate ran");
        assertEquals(ChangeDisposition.COMMITTED_PENDING_VALIDATION, outcome.disposition());
        assertFalse(baseSha.equals(git.currentHeadSha(repo)), "the commit must still be on the branch");
        assertTrue(outcome.fullBuildRan());
        assertFalse(outcome.fullyBuildValidated());
        assertEquals(ValidationStatus.FAILED, outcome.fullBuildValidation().status());
        assertTrue(outcome.fullBuildValidation().reason().contains("tests failed in module x"),
                outcome.fullBuildValidation().reason());

        // Bug 6 regression (pilot 20260909-012226-8bfda1): a failed full build must be reflected in the
        // attempt's own dispositionReason too, never left reading as "nothing tested yet".
        String attempt = artifact(RemediationImplementationService.ATTEMPT_FILE);
        assertFalse(attempt.contains("nothing has compiled or tested"), attempt);
        assertTrue(attempt.contains("the full build failed"), attempt);
        assertTrue(attempt.contains("tests failed in module x"), attempt);
    }

    // ---- Bug 6 regression: describeDisposition never leaves a stale COMMITTED_PENDING_VALIDATION-era
    // sentence sitting next to an already-known full-build result (pilot 20260909-012226-8bfda1) ----------

    private static final ChangeOutcome COMMITTED_PENDING = new ChangeOutcome(
            ChangeDisposition.COMMITTED_PENDING_VALIDATION, "abc123", "", List.of(),
            "Committed on the remediation branch; nothing has compiled or tested it yet.", null);

    @Test
    @DisplayName("describeDisposition: a fresh commit with no full-build outcome yet keeps the original, "
            + "still-accurate pending sentence")
    void describeDispositionPendingWhenFullBuildOutcomeUnknown() {
        assertEquals("Committed on the remediation branch; nothing has compiled or tested it yet.",
                RemediationImplementationService.describeDisposition(COMMITTED_PENDING, null));
    }

    @Test
    @DisplayName("describeDisposition: a passed full build produces a fresh success sentence with no trace "
            + "of \"nothing tested yet\"")
    void describeDispositionSuccessWhenFullBuildPassed() {
        ValidationOutcome passed = ValidationOutcome.passed(
                "The full build succeeded: mvn.cmd -B clean package exited 0.", List.of(), "output");

        String reason = RemediationImplementationService.describeDisposition(COMMITTED_PENDING, passed);

        assertFalse(reason.contains("nothing has compiled or tested"), reason);
        assertTrue(reason.contains("successfully passed dependency validation and full build validation"), reason);
    }

    @Test
    @DisplayName("describeDisposition: a failed full build produces a failure-specific sentence naming why")
    void describeDispositionFailureWhenFullBuildFailed() {
        ValidationOutcome failed = ValidationOutcome.failed(
                "The full build failed: mvn.cmd -B clean package exited with code 1.", List.of(), "output");

        String reason = RemediationImplementationService.describeDisposition(COMMITTED_PENDING, failed);

        assertFalse(reason.contains("nothing has compiled or tested"), reason);
        assertTrue(reason.contains("the full build failed"), reason);
        assertTrue(reason.contains("exited with code 1"), reason);
    }

    @Test
    @DisplayName("describeDisposition: a rolled-back disposition's own reason is returned unchanged, "
            + "whatever the full-build outcome is")
    void describeDispositionRolledBackReasonUnchanged() {
        ChangeOutcome rolledBack = new ChangeOutcome(ChangeDisposition.ROLLED_BACK, null, "", List.of(),
                "The implementation did not complete the remediation, so the partial changes it had "
                        + "already made were undone.", null);

        assertEquals(rolledBack.reason(), RemediationImplementationService.describeDisposition(rolledBack, null));
    }

    @Test
    @DisplayName("the full build is skipped entirely when the implementation was rolled back")
    void fullBuildSkippedWhenRolledBack() throws Exception {
        FakeClaude fake = fakeAnswering(
                Assessments.answerContaining(Implementations.contradictedJson()),
                "pom.xml", "<project>half-done</project>\n");

        ImplementationOutcome outcome = implementWith(fake,
                Implementations.passingGate(), Implementations.passingBuildGate());

        assertFalse(outcome.committed());
        assertFalse(outcome.fullBuildRan(), "there is nothing to build-validate when nothing was committed");
        assertEquals("", artifact(RemediationImplementationService.FULL_BUILD_VALIDATION_FILE));
        assertEquals("", artifact(RemediationImplementationService.FULL_BUILD_OUTPUT_FILE));
    }

    @Test
    @DisplayName("the full build is skipped when the dependency-resolution gate itself refused the commit")
    void fullBuildSkippedWhenDependencyGateRefuses() throws Exception {
        FakeClaude fake = fakeAnswering(
                Assessments.answerContaining(Implementations.completedJson()),
                "pom.xml", "<project><bouncycastle.version>1.85</bouncycastle.version></project>\n");

        ImplementationOutcome outcome = implementWith(fake,
                Implementations.failingGate("bcprov still resolves to 1.84"),
                Implementations.passingBuildGate());

        assertFalse(outcome.committed());
        assertFalse(outcome.fullBuildRan());
    }

    @Test
    @DisplayName("full-build artifacts land in the same attempt directory as everything else")
    void fullBuildArtifactsLandInTheAttemptDirectory() throws Exception {
        FakeClaude fake = fakeAnswering(Implementations.completedJson(),
                "pom.xml", "<project/>\n");

        implementWith(fake, Implementations.passingGate(), Implementations.passingBuildGate());

        assertTrue(Files.exists(directory().resolve(RemediationImplementationService.FULL_BUILD_VALIDATION_FILE)));
        assertTrue(Files.exists(directory().resolve(RemediationImplementationService.FULL_BUILD_OUTPUT_FILE)));
    }

    @Test
    @DisplayName("the full build stage announces itself live: starting, heartbeat, and how it finished")
    void fullBuildStageReportsLiveProgress() throws Exception {
        FakeClaude fake = fakeAnswering(Implementations.completedJson(), "pom.xml", "<project/>\n");
        List<String> events = new ArrayList<>();
        RemediationProgressListener capturing = new RemediationProgressListener() {
            @Override
            public void stepStarting(RemediationStep step, String coordinates, String detail) {
                events.add("start:" + step);
            }

            @Override
            public void stepFinished(RemediationStep step, String coordinates, String outcome) {
                events.add("finish:" + step + ":" + outcome);
            }
        };
        FullBuildValidationGate heartbeatingGate = (request, heartbeat) -> {
            heartbeat.run();
            heartbeat.run();
            return ValidationOutcome.passed("ok", List.of("stub"), "stub output");
        };

        service(fake, new ImplementationPromptRenderer(), Implementations.passingGate(), heartbeatingGate,
                capturing).implement(Implementations.context(repo, baseSha));

        assertTrue(events.contains("start:FULL_BUILD_VALIDATION"), events.toString());
        assertTrue(events.contains("finish:FULL_BUILD_VALIDATION:PASSED"), events.toString());
    }

    /** Runs {@code implement} against the standard context, with an explicit gate/build-gate pair. */
    private ImplementationOutcome implementWith(
            FakeClaude fake, RemediationValidationGate gate, FullBuildValidationGate buildGate)
            throws Exception {
        return service(fake, new ImplementationPromptRenderer(), gate, buildGate)
                .implement(Implementations.context(repo, baseSha));
    }
}
