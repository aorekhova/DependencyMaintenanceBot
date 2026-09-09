package com.tungsten.depbot.claude;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ClaudeRunRequestTest {

    private static final ClaudeConfig CONFIG =
            new ClaudeConfig("claude", "opus", 30, Duration.ofSeconds(600));
    private static final Path WORKSPACE = Path.of("workspace");
    private static final Path ATTEMPT = Path.of("attempt");

    private static ClaudeRunRequest request(ClaudePhase phase) {
        return ClaudeRunRequest.of(phase, WORKSPACE, "do the thing", ATTEMPT, CONFIG);
    }

    @ParameterizedTest
    @EnumSource(ClaudePhase.class)
    @DisplayName("a request takes the phase's own tool policy and the configured limits")
    void requestTakesThePhasePolicyAndConfiguredLimits(ClaudePhase phase) {
        ClaudeRunRequest request = request(phase);

        assertEquals(ClaudeToolPolicy.forPhase(phase), request.toolPolicy());
        assertEquals(CONFIG.maxTurnsFor(phase), request.maxTurns());
        assertEquals(CONFIG.timeoutFor(phase), request.timeout());
    }

    @Test
    @DisplayName("every phase gets its own turn budget, not the shared default")
    void eachPhaseGetsItsOwnTurnBudget() {
        assertEquals(ClaudeConfig.DEFAULT_ANALYSIS_MAX_TURNS, request(ClaudePhase.ASSESSMENT).maxTurns());
        assertEquals(ClaudeConfig.DEFAULT_IMPLEMENTATION_MAX_TURNS,
                request(ClaudePhase.IMPLEMENTATION).maxTurns());
        assertEquals(ClaudeConfig.DEFAULT_HUMAN_REVIEW_MAX_TURNS, request(ClaudePhase.HUMAN_REVIEW).maxTurns());
    }

    @Test
    @DisplayName("every phase gets its own timeout, not the shared one")
    void eachPhaseGetsItsOwnTimeout() {
        ClaudeConfig config = new ClaudeConfig("claude", "opus", 30, Duration.ofSeconds(1800));

        assertEquals(Duration.ofSeconds(ClaudeConfig.DEFAULT_ANALYSIS_TIMEOUT_SECONDS),
                ClaudeRunRequest.of(ClaudePhase.ASSESSMENT, WORKSPACE, "do the thing", ATTEMPT, config)
                        .timeout());
        assertEquals(Duration.ofSeconds(ClaudeConfig.DEFAULT_IMPLEMENTATION_TIMEOUT_SECONDS),
                ClaudeRunRequest.of(ClaudePhase.IMPLEMENTATION, WORKSPACE, "do the thing", ATTEMPT, config)
                        .timeout(),
                "the shared timeout (1800s) passed to the 4-arg constructor must not apply to any phase "
                        + "any more, now that every phase has its own default too");
        assertEquals(Duration.ofSeconds(ClaudeConfig.DEFAULT_HUMAN_REVIEW_TIMEOUT_SECONDS),
                ClaudeRunRequest.of(ClaudePhase.HUMAN_REVIEW, WORKSPACE, "do the thing", ATTEMPT, config)
                        .timeout());
    }

    @Test
    @DisplayName("the prompt is carried verbatim, so what a service composed is what Claude reads")
    void promptIsCarriedVerbatim() {
        String prompt = "# Assessment\n\nline two\n";

        assertEquals(prompt, ClaudeRunRequest.of(
                ClaudePhase.ASSESSMENT, WORKSPACE, prompt, ATTEMPT, CONFIG).prompt());
    }

    @Test
    @DisplayName("the output document's location is derived from the attempt directory, not guessed")
    void stdoutFileIsDerivedFromTheAttemptDirectory() {
        assertEquals(ATTEMPT.resolve(ClaudeArtifacts.STDOUT_FILE),
                request(ClaudePhase.ASSESSMENT).stdoutFile());
    }

    @Test
    @DisplayName("a blank prompt is rejected, since there would be nothing to ask")
    void blankPromptIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> ClaudeRunRequest.of(
                ClaudePhase.ASSESSMENT, WORKSPACE, "   ", ATTEMPT, CONFIG));
    }

    @Test
    @DisplayName("a non-positive turn limit or timeout is rejected at construction")
    void nonPositiveLimitsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new ClaudeRunRequest(
                ClaudePhase.ASSESSMENT, WORKSPACE, "ask", ATTEMPT,
                ClaudeToolPolicy.forAssessment(), 0, Duration.ofSeconds(60)));
        assertThrows(IllegalArgumentException.class, () -> new ClaudeRunRequest(
                ClaudePhase.ASSESSMENT, WORKSPACE, "ask", ATTEMPT,
                ClaudeToolPolicy.forAssessment(), 5, Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new ClaudeRunRequest(
                ClaudePhase.ASSESSMENT, WORKSPACE, "ask", ATTEMPT,
                ClaudeToolPolicy.forAssessment(), 5, Duration.ofSeconds(-1)));
    }

    @Test
    @DisplayName("every part of a request is required")
    void everyPartIsRequired() {
        assertThrows(NullPointerException.class, () -> new ClaudeRunRequest(
                null, WORKSPACE, "ask", ATTEMPT, ClaudeToolPolicy.forAssessment(), 5, Duration.ofSeconds(60)));
        assertThrows(NullPointerException.class, () -> new ClaudeRunRequest(
                ClaudePhase.ASSESSMENT, null, "ask", ATTEMPT, ClaudeToolPolicy.forAssessment(), 5,
                Duration.ofSeconds(60)));
        assertThrows(NullPointerException.class, () -> new ClaudeRunRequest(
                ClaudePhase.ASSESSMENT, WORKSPACE, null, ATTEMPT, ClaudeToolPolicy.forAssessment(), 5,
                Duration.ofSeconds(60)));
        assertThrows(NullPointerException.class, () -> new ClaudeRunRequest(
                ClaudePhase.ASSESSMENT, WORKSPACE, "ask", null, ClaudeToolPolicy.forAssessment(), 5,
                Duration.ofSeconds(60)));
        assertThrows(NullPointerException.class, () -> new ClaudeRunRequest(
                ClaudePhase.ASSESSMENT, WORKSPACE, "ask", ATTEMPT, null, 5, Duration.ofSeconds(60)));
    }

    @Test
    @DisplayName("an ordinary request carries no session to resume")
    void ordinaryRequestHasNoResumeSessionId() {
        assertNull(request(ClaudePhase.ASSESSMENT).resumeSessionId());
        assertNull(new ClaudeRunRequest(
                ClaudePhase.ASSESSMENT, WORKSPACE, "ask", ATTEMPT, ClaudeToolPolicy.forAssessment(), 5,
                Duration.ofSeconds(60)).resumeSessionId());
    }

    // ---- the assessment finalization request --------------------------------------------------

    @Test
    @DisplayName("a finalization request uses the no-tools policy and its own, smaller turn budget")
    void finalizationRequestUsesTheFinalizationProfileAndBudget() {
        ClaudeRunRequest request = ClaudeRunRequest.ofAssessmentFinalization(
                WORKSPACE, "write it up now", ATTEMPT, CONFIG, null);

        assertEquals(ClaudeToolPolicy.forAssessmentFinalization(), request.toolPolicy());
        assertEquals(CONFIG.analysisFinalizationMaxTurns(), request.maxTurns());
        assertEquals(CONFIG.timeout(), request.timeout());
        assertNull(request.resumeSessionId());
    }

    @Test
    @DisplayName("a finalization request carries the session id through to resumeSessionId, when given one")
    void finalizationRequestCarriesTheSessionIdThrough() {
        ClaudeRunRequest request = ClaudeRunRequest.ofAssessmentFinalization(
                WORKSPACE, "write it up now", ATTEMPT, CONFIG, "sess-real-1234");

        assertEquals("sess-real-1234", request.resumeSessionId());
    }

    // ---- the implementation finalization request -----------------------------------------------

    @Test
    @DisplayName("an implementation finalization request uses the read-only policy and its own turn budget")
    void implementationFinalizationRequestUsesTheFinalizationProfileAndBudget() {
        ClaudeRunRequest request = ClaudeRunRequest.ofImplementationFinalization(
                WORKSPACE, "report on it now", ATTEMPT, CONFIG, null);

        assertEquals(ClaudeToolPolicy.forImplementationFinalization(), request.toolPolicy());
        assertEquals(CONFIG.implementationFinalizationMaxTurns(), request.maxTurns());
        assertEquals(CONFIG.timeout(), request.timeout());
        assertNull(request.resumeSessionId());
    }

    @Test
    @DisplayName("an implementation finalization request carries the session id through, when given one")
    void implementationFinalizationRequestCarriesTheSessionIdThrough() {
        ClaudeRunRequest request = ClaudeRunRequest.ofImplementationFinalization(
                WORKSPACE, "report on it now", ATTEMPT, CONFIG, "sess-impl-1234");

        assertEquals("sess-impl-1234", request.resumeSessionId());
    }

    // ---- the human review finalization request --------------------------------------------------

    @Test
    @DisplayName("a human review finalization request uses the zero-tool policy and its own turn budget")
    void humanReviewFinalizationRequestUsesTheFinalizationProfileAndBudget() {
        ClaudeRunRequest request = ClaudeRunRequest.ofHumanReviewFinalization(
                WORKSPACE, "write it up now", ATTEMPT, CONFIG, null);

        assertEquals(ClaudeToolPolicy.forHumanReviewFinalization(), request.toolPolicy());
        assertEquals(CONFIG.humanReviewFinalizationMaxTurns(), request.maxTurns());
        assertEquals(CONFIG.timeout(), request.timeout());
        assertNull(request.resumeSessionId());
    }

    @Test
    @DisplayName("a human review finalization request carries the session id through, when given one")
    void humanReviewFinalizationRequestCarriesTheSessionIdThrough() {
        ClaudeRunRequest request = ClaudeRunRequest.ofHumanReviewFinalization(
                WORKSPACE, "write it up now", ATTEMPT, CONFIG, "sess-hr-1234");

        assertEquals("sess-hr-1234", request.resumeSessionId());
    }

    @Test
    @DisplayName("each phase has its own artifact directory name and prompt marker")
    void phasesAreDistinguishable() {
        assertEquals("assessment", ClaudePhase.ASSESSMENT.directoryName());
        assertEquals("implementation", ClaudePhase.IMPLEMENTATION.directoryName());

        String assessmentMarker = ClaudePhase.ASSESSMENT.promptMarker();
        String implementationMarker = ClaudePhase.IMPLEMENTATION.promptMarker();

        org.junit.jupiter.api.Assertions.assertFalse(assessmentMarker.contains("IMPLEMENTATION"));
        org.junit.jupiter.api.Assertions.assertFalse(implementationMarker.contains("ASSESSMENT"));
        org.junit.jupiter.api.Assertions.assertTrue(
                assessmentMarker.contains(ClaudePhase.MARKER_PREFIX), assessmentMarker);
        org.junit.jupiter.api.Assertions.assertTrue(
                implementationMarker.contains(ClaudePhase.MARKER_PREFIX), implementationMarker);
    }
}
