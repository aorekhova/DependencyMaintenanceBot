package com.tungsten.depbot.assessment;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.claude.ClaudeCodeExecutor;
import com.tungsten.depbot.claude.ClaudeConfig;
import com.tungsten.depbot.claude.ClaudePhase;
import com.tungsten.depbot.claude.ClaudeProcessRunner;
import com.tungsten.depbot.claude.FakeClaude;
import com.tungsten.depbot.run.RemediationRunService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fast, targeted regression tests for the two-attempt Vulnerability Analysis scheme and the coverage
 * gate in {@link BatchAnalysisService}. Deliberately minimal -- a {@link FakeClaude} executable and a
 * temporary directory, no real Claude, Mend, Jenkins or GitLab, no network. Each test runs in well
 * under a second except the genuine wall-clock timeout cases, which use a one-second configured
 * timeout rather than a real production one.
 */
class BatchAnalysisServiceTest {

    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-08-10T10:00:00Z"), ZoneOffset.UTC);
    private static final String RUN_ID = "run1";

    @TempDir
    Path tempDir;

    private Path workspace;
    private final JsonMapper mapper = JsonMapper.builder().build();

    @BeforeEach
    void createWorkspace() throws IOException {
        workspace = tempDir.resolve("workspace");
        Files.createDirectories(workspace);
    }

    private Path runsRoot() {
        return tempDir.resolve("runs");
    }

    private ClaudeConfig config(FakeClaude fake) {
        return new ClaudeConfig(fake.executable().toString(), "opus", 20, Duration.ofSeconds(60));
    }

    /**
     * A deliberately short <em>first-attempt</em> timeout, to exercise the real wall-clock timeout path
     * without waiting out a production-sized budget. The second attempt's own timeout is generous
     * (30s), not tight: it is always answered by a scripted, non-sleeping response, never a real sleep,
     * so a generous budget costs nothing in the ordinary case -- it only exists to give a scripted
     * response enough real wall-clock margin under a heavily loaded, concurrent full-suite run, where
     * this environment's own process-spawn latency is known to vary.
     */
    private ClaudeConfig impatientConfig(FakeClaude fake) {
        return new ClaudeConfig(fake.executable().toString(), "opus", 20,
                ClaudeConfig.DEFAULT_ANALYSIS_MAX_TURNS, ClaudeConfig.DEFAULT_IMPLEMENTATION_MAX_TURNS,
                ClaudeConfig.DEFAULT_HUMAN_REVIEW_MAX_TURNS,
                ClaudeConfig.DEFAULT_ANALYSIS_FINALIZATION_MAX_TURNS,
                ClaudeConfig.DEFAULT_IMPLEMENTATION_FINALIZATION_MAX_TURNS,
                ClaudeConfig.DEFAULT_HUMAN_REVIEW_FINALIZATION_MAX_TURNS,
                Duration.ofSeconds(60), Duration.ofSeconds(1),
                Duration.ofSeconds(ClaudeConfig.DEFAULT_IMPLEMENTATION_TIMEOUT_SECONDS),
                Duration.ofSeconds(ClaudeConfig.DEFAULT_HUMAN_REVIEW_TIMEOUT_SECONDS),
                ClaudeConfig.DEFAULT_ANALYSIS_SECOND_ATTEMPT_MAX_TURNS, Duration.ofSeconds(30));
    }

    private BatchAnalysisService service(FakeClaude fake, ClaudeConfig config) {
        RemediationRunService runService = new RemediationRunService(FIXED_CLOCK, runsRoot());
        return new BatchAnalysisService(
                new ClaudeCodeExecutor(config, new ClaudeProcessRunner(), runService, FIXED_CLOCK),
                config, runService, new BatchAnalysisPromptRenderer());
    }

    private AnalysisContext context(VulnerabilityWorkItem... items) {
        return new AnalysisContext(RUN_ID, workspace, "master", "abc1234def5678", true, List.of(items));
    }

    private BatchAnalysisAttempt readAttempt(BatchAnalysisService service) throws IOException {
        Path path = service.analysisDirectoryFor(RUN_ID).resolve(BatchAnalysisService.ATTEMPT_FILE);
        return mapper.readValue(path.toFile(), BatchAnalysisAttempt.class);
    }

    private PartialAnalysisState readPartialState(BatchAnalysisService service) throws IOException {
        Path path = service.analysisDirectoryFor(RUN_ID).resolve(BatchAnalysisService.PARTIAL_ANALYSIS_STATE_FILE);
        return mapper.readValue(path.toFile(), PartialAnalysisState.class);
    }

    /** A batch analysis document where every finding is an unreached-placeholder INCONCLUSIVE. */
    private static String placeholderAnalysisJson(String... coordinates) {
        StringBuilder findings = new StringBuilder();
        for (int i = 0; i < coordinates.length; i++) {
            if (i > 0) {
                findings.append(",\n");
            }
            findings.append("""
                    {
                      "coordinates": "%s",
                      "vulnerabilityIds": ["CVE-2026-1"],
                      "summary": "Not examined",
                      "conclusion": "INCONCLUSIVE",
                      "remediationGroupId": null,
                      "evidence": [],
                      "risks": ["time ran out before this finding could be looked at"]
                    }""".formatted(coordinates[i]));
        }
        return """
                {
                  "schemaVersion": "1.0",
                  "findings": [
                %s
                  ],
                  "remediationGroups": []
                }
                """.formatted(findings.toString().indent(4));
    }

    // ---- 1. attempt1 timeout + attempt2 answers with unreached placeholders -> INCOMPLETE ----------

    @Test
    @DisplayName("attempt1 timeout + attempt2 answering every finding with an unreached placeholder "
            + "-> INCOMPLETE, never treated as a usable analysis")
    void secondAttemptAllPlaceholderFindingsMarksAnalysisIncomplete() throws Exception {
        VulnerabilityWorkItem workItem = Assessments.workItem();
        FakeClaude fake = FakeClaude.in(tempDir)
                .sleepingFor(5)
                .respondingToAssessmentSecondAttempt(
                        Assessments.claudeOutput(placeholderAnalysisJson(workItem.coordinates())))
                .build();

        BatchAnalysisService service = service(fake, impatientConfig(fake));
        BatchAnalysisOutcome outcome = service.analyze(context(workItem));

        assertEquals(BatchAnalysisStatus.INCOMPLETE, outcome.status());
        assertFalse(outcome.hasAnalysis(), "an incomplete document must never be treated as routable");
        assertFalse(outcome.isPartial(), "a coverage failure is INCOMPLETE, not PARTIAL -- attempt2 did answer");
        assertTrue(outcome.isIncomplete());
        assertNotNull(outcome.incompleteReason());
        assertTrue(outcome.incompleteReason().contains(workItem.coordinates()), outcome.incompleteReason());

        Path directory = service.analysisDirectoryFor(RUN_ID);
        assertFalse(Files.exists(directory.resolve(BatchAnalysisService.ANALYSIS_FILE)),
                "an incomplete result must never be written under the name that means \"safe to route\"");
        assertTrue(Files.exists(directory.resolve(BatchAnalysisService.INCOMPLETE_ANALYSIS_FILE)),
                "the untrusted document is still preserved on disk for a human to inspect");

        BatchAnalysisAttempt attempt = readAttempt(service);
        assertFalse(attempt.analysisUsable());
        assertEquals(BatchAnalysisStatus.INCOMPLETE, attempt.status());
        assertTrue(attempt.timedOut(), "the top-level flat fields describe attempt1");
    }

    // ---- 2. attempt1 max-turns is preserved separately from a genuine timeout -----------------------

    @Test
    @DisplayName("attempt1 hitting the turn limit is recorded as MAX_TURNS_EXCEEDED, never as a timeout")
    void firstAttemptMaxTurnsExceededIsPreservedSeparatelyFromTimeout() throws Exception {
        VulnerabilityWorkItem workItem = Assessments.workItem();
        String primaryResponse = "{\"is_error\":true,\"subtype\":\"error_max_turns\",\"session_id\":\"sess-1\"}";
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, primaryResponse)
                .respondingToAssessmentSecondAttempt(
                        Assessments.claudeOutput(placeholderAnalysisJson(workItem.coordinates())))
                .build();

        BatchAnalysisService service = service(fake, config(fake));
        BatchAnalysisOutcome outcome = service.analyze(context(workItem));

        assertTrue(outcome.isIncomplete());

        BatchAnalysisAttempt attempt = readAttempt(service);
        assertEquals(AnalysisInvocationOutcomeReason.MAX_TURNS_EXCEEDED, attempt.attempt1().outcomeReason());
        assertTrue(attempt.attempt1().maxTurnsExceeded());
        assertFalse(attempt.attempt1().timedOut(),
                "error_max_turns must never be reported as a wall-clock timeout");
        assertFalse(attempt.timedOut(), "the top-level flat field mirrors attempt1, not a timeout");
    }

    // ---- 3. attempt1 and attempt2 metadata never overwrite each other ---------------------------

    @Test
    @DisplayName("attempt1 and attempt2 invocation metadata are kept fully separate, never conflated")
    void firstAndSecondAttemptMetadataAreNeverConflated() throws Exception {
        VulnerabilityWorkItem workItem = Assessments.workItem();
        FakeClaude fake = FakeClaude.in(tempDir)
                .sleepingFor(5)
                .respondingToAssessmentSecondAttempt(
                        Assessments.claudeOutput(placeholderAnalysisJson(workItem.coordinates())))
                .build();

        BatchAnalysisService service = service(fake, impatientConfig(fake));
        service.analyze(context(workItem));

        BatchAnalysisAttempt attempt = readAttempt(service);
        assertNotNull(attempt.attempt1());
        assertNotNull(attempt.attempt2());

        // attempt1 was killed by the wall-clock timeout: it never reached its own answer.
        assertTrue(attempt.attempt1().timedOut());
        assertEquals(AnalysisInvocationOutcomeReason.PROCESS_TIMEOUT, attempt.attempt1().outcomeReason());
        assertFalse(attempt.attempt1().analysisUsable());

        // attempt2 completed cleanly and produced a structurally valid (if untrusted) document.
        assertFalse(attempt.attempt2().timedOut());
        assertEquals(AnalysisInvocationOutcomeReason.COMPLETED, attempt.attempt2().outcomeReason());

        // The bug this fixes: the top-level flat fields must describe attempt1, never be overwritten by
        // attempt2's own (here, deliberately different) facts.
        assertEquals(attempt.attempt1().timedOut(), attempt.timedOut());
        assertEquals(attempt.attempt1().startedAt(), attempt.startedAt());
        assertEquals(attempt.attempt1().finishedAt(), attempt.finishedAt());
        assertNotEquals(attempt.attempt2().command(), attempt.command(),
                "attempt2's own distinct command line must never overwrite attempt1's");
    }

    // ---- 4. a genuinely complete second attempt is still accepted -----------------------------

    @Test
    @DisplayName("a second attempt that genuinely reconstructs real conclusions is still accepted as complete")
    void genuinelyCompleteSecondAttemptIsStillAccepted() throws Exception {
        VulnerabilityWorkItem workItem = Assessments.workItem();
        String primaryResponse = "{\"is_error\":true,\"subtype\":\"error_max_turns\",\"session_id\":\"sess-2\"}";
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, primaryResponse)
                .respondingToAssessmentSecondAttempt(Assessments.claudeOutput(Assessments.json()))
                .build();

        BatchAnalysisService service = service(fake, config(fake));
        BatchAnalysisOutcome outcome = service.analyze(context(workItem));

        assertEquals(BatchAnalysisStatus.COMPLETE, outcome.status());
        assertTrue(outcome.hasAnalysis());
        assertFalse(outcome.isIncomplete());
        assertFalse(outcome.isPartial());
        assertNotNull(outcome.analysis());
        assertEquals(1, outcome.analysis().findings().size());

        Path directory = service.analysisDirectoryFor(RUN_ID);
        assertTrue(Files.exists(directory.resolve(BatchAnalysisService.ANALYSIS_FILE)));
        assertFalse(Files.exists(directory.resolve(BatchAnalysisService.INCOMPLETE_ANALYSIS_FILE)));

        BatchAnalysisAttempt attempt = readAttempt(service);
        assertTrue(attempt.analysisUsable());
        assertTrue(attempt.secondAttemptUsed());
        assertEquals(BatchAnalysisStatus.COMPLETE, attempt.status());
    }

    // ---- 5. both attempts running out of room preserves progress, never masks as INCOMPLETE --------

    @Test
    @DisplayName("both attempts running out of turns or time -> PARTIAL, with both attempts' progress preserved")
    void bothAttemptsRunningOutOfRoomProducesPartialWithPreservedProgress() throws Exception {
        VulnerabilityWorkItem workItem = Assessments.workItem();
        String primaryResponse = "{\"is_error\":true,\"subtype\":\"error_max_turns\",\"session_id\":\"sess-3\"}";
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, primaryResponse)
                .respondingToAssessmentSecondAttempt(
                        "{\"is_error\":true,\"subtype\":\"error_max_turns\",\"session_id\":\"sess-3-cont\","
                                + "\"result\":\"looked at bcprov, still unsure of the exact fix\"}")
                .build();

        BatchAnalysisService service = service(fake, config(fake));
        BatchAnalysisOutcome outcome = service.analyze(context(workItem));

        assertEquals(BatchAnalysisStatus.PARTIAL, outcome.status());
        assertTrue(outcome.isPartial());
        assertFalse(outcome.hasAnalysis());
        assertFalse(outcome.isIncomplete(), "two attempts both running out of room is PARTIAL, not INCOMPLETE");
        assertNull(outcome.analysis());
        assertNotNull(outcome.partialAnalysisState());

        BatchAnalysisAttempt attempt = readAttempt(service);
        assertEquals(BatchAnalysisStatus.PARTIAL, attempt.status());
        assertEquals(AnalysisInvocationOutcomeReason.MAX_TURNS_EXCEEDED, attempt.attempt1().outcomeReason());
        assertEquals(AnalysisInvocationOutcomeReason.MAX_TURNS_EXCEEDED, attempt.attempt2().outcomeReason());

        PartialAnalysisState partial = readPartialState(service);
        assertNotNull(partial.attempt1());
        assertNotNull(partial.attempt2());
        assertTrue(partial.attempt2().hasRawResultText());
        assertTrue(partial.attempt2().rawResultText().contains("bcprov"),
                "attempt2's own raw text must be preserved, not discarded");
    }

    // ---- 6. schema-repair: a substantive but schema-malformed document gets one bounded repair ------
    //
    // Production defect (pilot 20260908-162700-b5dce6): Claude #1 completed a real, 74-turn investigation
    // and returned a substantive analysis, but one plannedChanges entry was missing its required
    // changeType -- Jackson could not bind it, and the whole batch was discarded as "no usable analysis,"
    // fanning all six findings out to individual Human Review. None of that is a timeout or
    // error_max_turns, so the old code went straight to recordFailed with no second attempt at all.

    /** Strips the first {@code "changeType": "..."} entry out of a batch analysis JSON document,
     *  reproducing exactly the malformed-output shape the production pilot hit. */
    private static String stripFirstChangeType(String json) {
        String stripped = json.replaceFirst("\"changeType\"\\s*:\\s*\"[A-Za-z_]+\"\\s*,\\s*\n", "");
        assertNotEquals(json, stripped, "the fixture must actually contain a changeType to strip");
        return stripped;
    }

    private static String withInvalidChangeType(String json) {
        return json.replaceFirst("\"changeType\"\\s*:\\s*\"[A-Za-z_]+\"", "\"changeType\": \"NOT_A_REAL_TYPE\"");
    }

    @Test
    @DisplayName("a substantive analysis missing one plannedChanges.changeType triggers exactly one "
            + "bounded schema-repair call, resuming the same session, and the repaired document is "
            + "accepted as COMPLETE")
    void missingChangeTypeTriggersOneSchemaRepairThenSucceeds() throws Exception {
        VulnerabilityWorkItem workItem = Assessments.workItem();
        String malformed = "{\"is_error\":false,\"subtype\":\"success\",\"type\":\"result\",\"session_id\":"
                + "\"sess-repair-1\",\"result\":" + jsonQuoted(Assessments.answerContaining(
                        stripFirstChangeType(Assessments.json()))) + "}";
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, malformed)
                .respondingToAssessmentSchemaRepair(Assessments.claudeOutput(Assessments.answerContaining(
                        Assessments.json())))
                .build();

        BatchAnalysisService service = service(fake, config(fake));
        BatchAnalysisOutcome outcome = service.analyze(context(workItem));

        assertEquals(BatchAnalysisStatus.COMPLETE, outcome.status());
        assertTrue(outcome.hasAnalysis());
        assertNotNull(outcome.analysis());
        assertEquals(List.of("assessment", "assessment-schema-repair"), fake.recordedPhaseSequence(),
                "exactly one repair call, never a real second investigation attempt");

        BatchAnalysisAttempt attempt = readAttempt(service);
        assertTrue(attempt.schemaRepairUsed());
        assertNotNull(attempt.schemaRepairAttempt());
        assertFalse(attempt.secondAttemptUsed(), "schema repair must never be recorded as attempt2");
        assertNull(attempt.attempt2(), "schema repair must never be conflated with the real second attempt");
        assertTrue(attempt.analysisUsable());
        assertEquals(AnalysisInvocationOutcomeReason.MALFORMED_ANALYSIS, attempt.attempt1().outcomeReason());
        assertEquals(AnalysisInvocationOutcomeReason.COMPLETED, attempt.schemaRepairAttempt().outcomeReason());

        // The repair prompt actually named the real error and resumed the same session -- never a fresh,
        // from-scratch re-investigation.
        String repairStdin = Files.readString(
                service.analysisDirectoryFor(RUN_ID).resolve(BatchAnalysisService.SCHEMA_REPAIR_SUBDIRECTORY)
                        .resolve("prompt.md"),
                java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(repairStdin.contains(BatchAnalysisSchemaRepairPromptRenderer.SCHEMA_REPAIR_MARKER));
        assertTrue(repairStdin.contains("changeType"), repairStdin);
        assertTrue(repairStdin.contains("Do not redo vulnerability research"), repairStdin);
        assertTrue(repairStdin.contains("continues your own session"), repairStdin);
    }

    @Test
    @DisplayName("an invalid changeType enum value triggers the same single schema-repair path")
    void invalidChangeTypeEnumTriggersOneSchemaRepairThenSucceeds() throws Exception {
        VulnerabilityWorkItem workItem = Assessments.workItem();
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(
                        Assessments.answerContaining(withInvalidChangeType(Assessments.json()))))
                .respondingToAssessmentSchemaRepair(Assessments.claudeOutput(
                        Assessments.answerContaining(Assessments.json())))
                .build();

        BatchAnalysisService service = service(fake, config(fake));
        BatchAnalysisOutcome outcome = service.analyze(context(workItem));

        assertEquals(BatchAnalysisStatus.COMPLETE, outcome.status());
        assertTrue(outcome.hasAnalysis());
        assertEquals(List.of("assessment", "assessment-schema-repair"), fake.recordedPhaseSequence());

        BatchAnalysisAttempt attempt = readAttempt(service);
        assertTrue(attempt.schemaRepairUsed());
        assertEquals(AnalysisInvocationOutcomeReason.MALFORMED_ANALYSIS, attempt.attempt1().outcomeReason());
    }

    @Test
    @DisplayName("when the one bounded schema-repair attempt is ALSO malformed, there is no second repair "
            + "-- the existing unusable-analysis (FAILED) fallback applies")
    void repairStillMalformedFallsBackToExistingFailedPathWithNoSecondRepair() throws Exception {
        VulnerabilityWorkItem workItem = Assessments.workItem();
        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(
                        Assessments.answerContaining(stripFirstChangeType(Assessments.json()))))
                .respondingToAssessmentSchemaRepair(Assessments.claudeOutput(
                        Assessments.answerContaining(stripFirstChangeType(Assessments.json()))))
                .build();

        BatchAnalysisService service = service(fake, config(fake));
        BatchAnalysisOutcome outcome = service.analyze(context(workItem));

        assertEquals(BatchAnalysisStatus.FAILED, outcome.status());
        assertFalse(outcome.hasAnalysis());
        assertNull(outcome.analysis());
        assertEquals(List.of("assessment", "assessment-schema-repair"), fake.recordedPhaseSequence(),
                "the repair call happens exactly once, never a second repair attempt even though it also "
                        + "failed");

        BatchAnalysisAttempt attempt = readAttempt(service);
        assertTrue(attempt.schemaRepairUsed());
        assertNotNull(attempt.schemaRepairAttempt());
        assertFalse(attempt.analysisUsable());
        assertEquals(AnalysisInvocationOutcomeReason.MALFORMED_ANALYSIS,
                attempt.schemaRepairAttempt().outcomeReason());

        Path directory = service.analysisDirectoryFor(RUN_ID);
        assertFalse(Files.exists(directory.resolve(BatchAnalysisService.ANALYSIS_FILE)));
    }

    @Test
    @DisplayName("a genuine timeout still runs the real second attempt, never the schema-repair path -- "
            + "existing timeout/MAX_TURNS semantics are unchanged")
    void genuineTimeoutStillUsesRealSecondAttemptNotSchemaRepair() throws Exception {
        VulnerabilityWorkItem workItem = Assessments.workItem();
        FakeClaude fake = FakeClaude.in(tempDir)
                .sleepingFor(5)
                .respondingToAssessmentSecondAttempt(
                        Assessments.claudeOutput(placeholderAnalysisJson(workItem.coordinates())))
                .build();

        BatchAnalysisService service = service(fake, impatientConfig(fake));
        BatchAnalysisOutcome outcome = service.analyze(context(workItem));

        assertTrue(outcome.isIncomplete());
        // attempt1 is killed mid-sleep by the wall-clock timeout, before its own script ever reaches the
        // line that records its phase -- the same reason the pre-existing timeout tests above never
        // assert on recordedPhaseSequence() including "assessment" either. What matters here is that the
        // real second-attempt marker is the one that ran, never a schema-repair marker.
        assertEquals(List.of("assessment-second-attempt"), fake.recordedPhaseSequence(),
                "a genuine timeout must still take the real second-attempt path, never schema-repair");

        BatchAnalysisAttempt attempt = readAttempt(service);
        assertTrue(attempt.secondAttemptUsed());
        assertFalse(attempt.schemaRepairUsed(), "a timeout must never be recorded as a schema repair");
        assertNull(attempt.schemaRepairAttempt());
    }

    @Test
    @DisplayName("production regression fixture: httpcomponents5-family with four DEPENDENCY_MANAGEMENT_ADDITION "
            + "plannedChanges initially missing changeType, plus one correct OTHER entry -- repair supplies "
            + "the missing changeTypes and the batch becomes routable")
    void httpComponents5FamilyRegressionFixture() throws Exception {
        VulnerabilityWorkItem workItem = new VulnerabilityWorkItem(
                "org.apache.httpcomponents.core5", "httpcore5", "5.2", "HIGH", "5.3", List.of());

        String malformedGroup = httpComponents5FamilyJson(false);
        String repairedGroup = httpComponents5FamilyJson(true);

        FakeClaude fake = FakeClaude.in(tempDir)
                .respondingTo(ClaudePhase.ASSESSMENT, Assessments.claudeOutput(
                        Assessments.answerContaining(malformedGroup)))
                .respondingToAssessmentSchemaRepair(Assessments.claudeOutput(
                        Assessments.answerContaining(repairedGroup)))
                .build();

        BatchAnalysisService service = service(fake, config(fake));
        BatchAnalysisOutcome outcome = service.analyze(context(workItem));

        assertEquals(BatchAnalysisStatus.COMPLETE, outcome.status());
        assertTrue(outcome.hasAnalysis());
        assertEquals(List.of("assessment", "assessment-schema-repair"), fake.recordedPhaseSequence());

        AnalysisRemediationGroup group = outcome.analysis().remediationGroups().get(0);
        assertEquals(5, group.plannedChanges().size());
        long dependencyManagementAdditions = group.plannedChanges().stream()
                .filter(change -> change.changeType() == PlannedChangeType.DEPENDENCY_MANAGEMENT_ADDITION)
                .count();
        assertEquals(4, dependencyManagementAdditions);
        long otherCount = group.plannedChanges().stream()
                .filter(change -> change.changeType() == PlannedChangeType.OTHER).count();
        assertEquals(1, otherCount);

        BatchAnalysisAttempt attempt = readAttempt(service);
        assertTrue(attempt.schemaRepairUsed());
    }

    /** The exact httpcomponents5-family shape from the production pilot: four DEPENDENCY_MANAGEMENT_ADDITION
     *  entries (missing changeType when {@code withChangeTypes} is false) plus one correct OTHER entry. */
    private static String httpComponents5FamilyJson(boolean withChangeTypes) {
        String[] coordinates = {
                "org.apache.httpcomponents.core5:httpcore5",
                "org.apache.httpcomponents.core5:httpcore5-h2",
                "org.apache.httpcomponents.client5:httpclient5",
                "org.apache.httpcomponents.client5:httpclient5-cache"};
        StringBuilder plannedChanges = new StringBuilder();
        for (String coordinate : coordinates) {
            if (plannedChanges.length() > 0) {
                plannedChanges.append(",\n");
            }
            String changeTypeLine = withChangeTypes ? "\"changeType\": \"DEPENDENCY_MANAGEMENT_ADDITION\"," : "";
            plannedChanges.append("""
                    {
                      "dependencyCoordinates": "%s",
                      "currentVersion": "5.2",
                      "targetVersion": "5.3",
                      "affectedFile": "pom.xml",
                      %s
                      "reason": "pin the new dependencyManagement entry to 5.3"
                    }""".formatted(coordinate, changeTypeLine));
        }
        plannedChanges.append(",\n").append("""
                {
                  "dependencyCoordinates": "org.apache.httpcomponents.client5:httpclient5",
                  "affectedFile": "pom.xml",
                  "changeType": "OTHER",
                  "reason": "regenerate the vendored NOTICE file listing these coordinates"
                }""");

        return """
                {
                  "schemaVersion": "1.0",
                  "findings": [
                    {
                      "coordinates": "org.apache.httpcomponents.core5:httpcore5",
                      "vulnerabilityIds": ["CVE-2026-9"],
                      "summary": "the httpcomponents5 family needs a coordinated bump",
                      "conclusion": "REMEDIATION_REQUIRED",
                      "remediationGroupId": "g-httpcomponents5-family",
                      "evidence": ["evidence"]
                    }
                  ],
                  "remediationGroups": [
                    {
                      "groupId": "g-httpcomponents5-family",
                      "memberCoordinates": ["org.apache.httpcomponents.core5:httpcore5"],
                      "groupingReason": "a coordinated dependency family",
                      "sourceRef": "origin/release/9.2",
                      "sourceCommitSha": "0123456789abcdef0123456789abcdef01234567",
                      "origin": "DEPENDENCY_MANAGEMENT",
                      "dependencyRelationship": "declared directly",
                      "observedVersion": "5.2",
                      "recommendedRemediation": "pin the httpcomponents5 family to 5.3 via dependencyManagement",
                      "recommendedTargetVersion": "5.3",
                      "affectedFiles": ["pom.xml"],
                      "impactScore": 3,
                      "impactReason": "four coordinated pins plus a generated notices file",
                      "automationSafety": "AUTOMATIC_ALLOWED",
                      "automationSafetyReason": "no coordinated or runtime-sensitive dependency is involved",
                      "implementationPlan": ["add dependencyManagement pins for the httpcomponents5 family"],
                      "validationPlan": ["run dependency:tree"],
                      "plannedChanges": [
                %s
                      ]
                    }
                  ]
                }
                """.formatted(plannedChanges.toString().indent(8));
    }

    private static String jsonQuoted(String value) {
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
}
