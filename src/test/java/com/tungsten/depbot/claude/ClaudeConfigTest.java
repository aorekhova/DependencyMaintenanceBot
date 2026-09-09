package com.tungsten.depbot.claude;

import com.tungsten.depbot.config.ConfigurationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ClaudeConfigTest {

    @Test
    @DisplayName("an empty environment yields the documented defaults, with opus as the model")
    void defaultsApply() {
        ClaudeConfig config = ClaudeConfig.fromEnvironment(Map.of());

        assertEquals("claude", config.executable());
        assertEquals("opus", config.model());
        assertEquals(ClaudeConfig.DEFAULT_MAX_TURNS, config.maxTurns());
        assertEquals(ClaudeConfig.DEFAULT_ANALYSIS_MAX_TURNS, config.analysisMaxTurns());
        assertEquals(ClaudeConfig.DEFAULT_IMPLEMENTATION_MAX_TURNS, config.implementationMaxTurns());
        assertEquals(ClaudeConfig.DEFAULT_ANALYSIS_FINALIZATION_MAX_TURNS,
                config.analysisFinalizationMaxTurns());
        assertEquals(ClaudeConfig.DEFAULT_IMPLEMENTATION_FINALIZATION_MAX_TURNS,
                config.implementationFinalizationMaxTurns());
        assertEquals(Duration.ofSeconds(ClaudeConfig.DEFAULT_TIMEOUT_SECONDS), config.timeout());
        assertEquals(Duration.ofSeconds(ClaudeConfig.DEFAULT_ANALYSIS_TIMEOUT_SECONDS),
                config.analysisTimeout());
        assertEquals(Duration.ofSeconds(ClaudeConfig.DEFAULT_IMPLEMENTATION_TIMEOUT_SECONDS),
                config.implementationTimeout());
    }

    @Test
    @DisplayName("a null environment does not throw and still yields defaults")
    void nullEnvironmentYieldsDefaults() {
        assertEquals("opus", ClaudeConfig.fromEnvironment(null).model());
    }

    @Test
    @DisplayName("every setting can be overridden through its environment variable")
    void everySettingIsConfigurable() {
        ClaudeConfig config = ClaudeConfig.fromEnvironment(Map.of(
                ClaudeConfig.CLAUDE_EXECUTABLE, "C:\\tools\\claude.cmd",
                ClaudeConfig.CLAUDE_MODEL, "claude-opus-5",
                ClaudeConfig.CLAUDE_MAX_TURNS, "7",
                ClaudeConfig.CLAUDE_ANALYSIS_MAX_TURNS, "45",
                ClaudeConfig.CLAUDE_IMPLEMENTATION_MAX_TURNS, "55",
                ClaudeConfig.CLAUDE_ANALYSIS_FINALIZATION_MAX_TURNS, "6",
                ClaudeConfig.CLAUDE_IMPLEMENTATION_FINALIZATION_MAX_TURNS, "9",
                ClaudeConfig.CLAUDE_TIMEOUT_SECONDS, "60",
                ClaudeConfig.CLAUDE_ANALYSIS_TIMEOUT_SECONDS, "120",
                ClaudeConfig.CLAUDE_IMPLEMENTATION_TIMEOUT_SECONDS, "240"));

        assertEquals("C:\\tools\\claude.cmd", config.executable());
        assertEquals("claude-opus-5", config.model());
        assertEquals(7, config.maxTurns());
        assertEquals(45, config.analysisMaxTurns());
        assertEquals(55, config.implementationMaxTurns());
        assertEquals(6, config.analysisFinalizationMaxTurns());
        assertEquals(9, config.implementationFinalizationMaxTurns());
        assertEquals(Duration.ofSeconds(240), config.implementationTimeout());
        assertEquals(Duration.ofSeconds(60), config.timeout());
        assertEquals(Duration.ofSeconds(120), config.analysisTimeout());
    }

    @Test
    @DisplayName("assessment's turn budget is configurable independently of the shared max turns and of "
            + "implementation's own budget")
    void analysisMaxTurnsIsConfigurableOnItsOwn() {
        ClaudeConfig config = ClaudeConfig.fromEnvironment(
                Map.of(ClaudeConfig.CLAUDE_ANALYSIS_MAX_TURNS, "90"));

        assertEquals(ClaudeConfig.DEFAULT_MAX_TURNS, config.maxTurns());
        assertEquals(90, config.analysisMaxTurns());
        assertEquals(ClaudeConfig.DEFAULT_IMPLEMENTATION_MAX_TURNS, config.implementationMaxTurns());
        assertEquals(90, config.maxTurnsFor(ClaudePhase.ASSESSMENT));
        assertEquals(ClaudeConfig.DEFAULT_IMPLEMENTATION_MAX_TURNS,
                config.maxTurnsFor(ClaudePhase.IMPLEMENTATION));
    }

    @Test
    @DisplayName("a non-numeric or non-positive assessment max turns is rejected the same way as the shared one")
    void analysisMaxTurnsValidatesLikeTheSharedOne() {
        ConfigurationException nonNumeric = assertThrows(ConfigurationException.class, () ->
                ClaudeConfig.fromEnvironment(Map.of(ClaudeConfig.CLAUDE_ANALYSIS_MAX_TURNS, "many")));
        assertEquals(true, nonNumeric.getMessage().contains(ClaudeConfig.CLAUDE_ANALYSIS_MAX_TURNS));

        assertThrows(ConfigurationException.class, () ->
                ClaudeConfig.fromEnvironment(Map.of(ClaudeConfig.CLAUDE_ANALYSIS_MAX_TURNS, "0")));
    }

    @Test
    @DisplayName("implementation's turn budget is configurable independently of the shared max turns and "
            + "of assessment's own budget")
    void implementationMaxTurnsIsConfigurableOnItsOwn() {
        ClaudeConfig config = ClaudeConfig.fromEnvironment(
                Map.of(ClaudeConfig.CLAUDE_IMPLEMENTATION_MAX_TURNS, "75"));

        assertEquals(ClaudeConfig.DEFAULT_MAX_TURNS, config.maxTurns());
        assertEquals(ClaudeConfig.DEFAULT_ANALYSIS_MAX_TURNS, config.analysisMaxTurns());
        assertEquals(75, config.implementationMaxTurns());
        assertEquals(ClaudeConfig.DEFAULT_ANALYSIS_MAX_TURNS, config.maxTurnsFor(ClaudePhase.ASSESSMENT));
        assertEquals(75, config.maxTurnsFor(ClaudePhase.IMPLEMENTATION));
    }

    @Test
    @DisplayName("a non-numeric or non-positive implementation max turns is rejected the same way as the "
            + "shared one")
    void implementationMaxTurnsValidatesLikeTheSharedOne() {
        ConfigurationException nonNumeric = assertThrows(ConfigurationException.class, () ->
                ClaudeConfig.fromEnvironment(Map.of(ClaudeConfig.CLAUDE_IMPLEMENTATION_MAX_TURNS, "many")));
        assertEquals(true, nonNumeric.getMessage().contains(ClaudeConfig.CLAUDE_IMPLEMENTATION_MAX_TURNS));

        assertThrows(ConfigurationException.class, () ->
                ClaudeConfig.fromEnvironment(Map.of(ClaudeConfig.CLAUDE_IMPLEMENTATION_MAX_TURNS, "0")));
    }

    @Test
    @DisplayName("assessment finalization's turn budget is configurable independently of every other budget")
    void analysisFinalizationMaxTurnsIsConfigurableOnItsOwn() {
        ClaudeConfig config = ClaudeConfig.fromEnvironment(
                Map.of(ClaudeConfig.CLAUDE_ANALYSIS_FINALIZATION_MAX_TURNS, "3"));

        assertEquals(ClaudeConfig.DEFAULT_MAX_TURNS, config.maxTurns());
        assertEquals(ClaudeConfig.DEFAULT_ANALYSIS_MAX_TURNS, config.analysisMaxTurns());
        assertEquals(ClaudeConfig.DEFAULT_IMPLEMENTATION_MAX_TURNS, config.implementationMaxTurns());
        assertEquals(3, config.analysisFinalizationMaxTurns());
    }

    @Test
    @DisplayName("a non-numeric or non-positive assessment finalization max turns is rejected the same way "
            + "as the shared one")
    void analysisFinalizationMaxTurnsValidatesLikeTheSharedOne() {
        ConfigurationException nonNumeric = assertThrows(ConfigurationException.class, () ->
                ClaudeConfig.fromEnvironment(
                        Map.of(ClaudeConfig.CLAUDE_ANALYSIS_FINALIZATION_MAX_TURNS, "many")));
        assertEquals(true,
                nonNumeric.getMessage().contains(ClaudeConfig.CLAUDE_ANALYSIS_FINALIZATION_MAX_TURNS));

        assertThrows(ConfigurationException.class, () -> ClaudeConfig.fromEnvironment(
                Map.of(ClaudeConfig.CLAUDE_ANALYSIS_FINALIZATION_MAX_TURNS, "0")));
    }

    @Test
    @DisplayName("implementation finalization's turn budget is configurable independently of every other "
            + "budget")
    void implementationFinalizationMaxTurnsIsConfigurableOnItsOwn() {
        ClaudeConfig config = ClaudeConfig.fromEnvironment(
                Map.of(ClaudeConfig.CLAUDE_IMPLEMENTATION_FINALIZATION_MAX_TURNS, "4"));

        assertEquals(ClaudeConfig.DEFAULT_MAX_TURNS, config.maxTurns());
        assertEquals(ClaudeConfig.DEFAULT_ANALYSIS_MAX_TURNS, config.analysisMaxTurns());
        assertEquals(ClaudeConfig.DEFAULT_IMPLEMENTATION_MAX_TURNS, config.implementationMaxTurns());
        assertEquals(ClaudeConfig.DEFAULT_ANALYSIS_FINALIZATION_MAX_TURNS,
                config.analysisFinalizationMaxTurns());
        assertEquals(4, config.implementationFinalizationMaxTurns());
    }

    @Test
    @DisplayName("a non-numeric or non-positive implementation finalization max turns is rejected the same "
            + "way as the shared one")
    void implementationFinalizationMaxTurnsValidatesLikeTheSharedOne() {
        ConfigurationException nonNumeric = assertThrows(ConfigurationException.class, () ->
                ClaudeConfig.fromEnvironment(
                        Map.of(ClaudeConfig.CLAUDE_IMPLEMENTATION_FINALIZATION_MAX_TURNS, "many")));
        assertEquals(true,
                nonNumeric.getMessage().contains(ClaudeConfig.CLAUDE_IMPLEMENTATION_FINALIZATION_MAX_TURNS));

        assertThrows(ConfigurationException.class, () -> ClaudeConfig.fromEnvironment(
                Map.of(ClaudeConfig.CLAUDE_IMPLEMENTATION_FINALIZATION_MAX_TURNS, "0")));
    }

    @Test
    @DisplayName("implementation's own budget is left exactly as it was, not increased for finalization")
    void implementationBudgetIsUnchanged() {
        assertEquals(60, ClaudeConfig.DEFAULT_IMPLEMENTATION_MAX_TURNS);
    }

    @Test
    @DisplayName("assessment's timeout is configurable independently of the shared timeout")
    void analysisTimeoutIsConfigurableOnItsOwn() {
        ClaudeConfig config = ClaudeConfig.fromEnvironment(
                Map.of(ClaudeConfig.CLAUDE_ANALYSIS_TIMEOUT_SECONDS, "300"));

        assertEquals(Duration.ofSeconds(ClaudeConfig.DEFAULT_TIMEOUT_SECONDS), config.timeout());
        assertEquals(Duration.ofSeconds(300), config.analysisTimeout());
        assertEquals(Duration.ofSeconds(300), config.timeoutFor(ClaudePhase.ASSESSMENT));
        assertEquals(Duration.ofSeconds(ClaudeConfig.DEFAULT_IMPLEMENTATION_TIMEOUT_SECONDS),
                config.timeoutFor(ClaudePhase.IMPLEMENTATION),
                "implementation must keep its own default timeout, unaffected by the assessment override");
    }

    @Test
    @DisplayName("a non-numeric or non-positive assessment timeout is rejected the same way as the shared one")
    void analysisTimeoutValidatesLikeTheSharedOne() {
        ConfigurationException nonNumeric = assertThrows(ConfigurationException.class, () ->
                ClaudeConfig.fromEnvironment(Map.of(ClaudeConfig.CLAUDE_ANALYSIS_TIMEOUT_SECONDS, "many")));
        assertEquals(true, nonNumeric.getMessage().contains(ClaudeConfig.CLAUDE_ANALYSIS_TIMEOUT_SECONDS));

        assertThrows(ConfigurationException.class, () ->
                ClaudeConfig.fromEnvironment(Map.of(ClaudeConfig.CLAUDE_ANALYSIS_TIMEOUT_SECONDS, "0")));
    }

    @Test
    @DisplayName("implementation's timeout is configurable independently of the shared and assessment timeouts")
    void implementationTimeoutIsConfigurableOnItsOwn() {
        ClaudeConfig config = ClaudeConfig.fromEnvironment(
                Map.of(ClaudeConfig.CLAUDE_IMPLEMENTATION_TIMEOUT_SECONDS, "900"));

        assertEquals(Duration.ofSeconds(ClaudeConfig.DEFAULT_TIMEOUT_SECONDS), config.timeout());
        assertEquals(Duration.ofSeconds(ClaudeConfig.DEFAULT_ANALYSIS_TIMEOUT_SECONDS),
                config.analysisTimeout());
        assertEquals(Duration.ofSeconds(900), config.implementationTimeout());
        assertEquals(Duration.ofSeconds(ClaudeConfig.DEFAULT_ANALYSIS_TIMEOUT_SECONDS),
                config.timeoutFor(ClaudePhase.ASSESSMENT),
                "assessment must keep its own default timeout, unaffected by the implementation override");
        assertEquals(Duration.ofSeconds(900), config.timeoutFor(ClaudePhase.IMPLEMENTATION));
    }

    @Test
    @DisplayName("a non-numeric or non-positive implementation timeout is rejected the same way as the "
            + "shared one")
    void implementationTimeoutValidatesLikeTheSharedOne() {
        ConfigurationException nonNumeric = assertThrows(ConfigurationException.class, () ->
                ClaudeConfig.fromEnvironment(
                        Map.of(ClaudeConfig.CLAUDE_IMPLEMENTATION_TIMEOUT_SECONDS, "many")));
        assertEquals(true,
                nonNumeric.getMessage().contains(ClaudeConfig.CLAUDE_IMPLEMENTATION_TIMEOUT_SECONDS));

        assertThrows(ConfigurationException.class, () ->
                ClaudeConfig.fromEnvironment(Map.of(ClaudeConfig.CLAUDE_IMPLEMENTATION_TIMEOUT_SECONDS, "0")));
    }

    @Test
    @DisplayName("the default budgets: 100 whole-batch analysis turns/30-minute timeout (placeholders, not "
            + "yet calibrated to a real batch size, raised after a real run needed more of both), 60 "
            + "implementation turns (unchanged)/15-minute implementation timeout (raised after a real "
            + "BouncyCastle remediation was cut off by the old 8-minute cap)")
    void defaultBudgetsMatchDocumentedPlaceholders() {
        assertEquals(100, ClaudeConfig.DEFAULT_ANALYSIS_MAX_TURNS);
        assertEquals(1800, ClaudeConfig.DEFAULT_ANALYSIS_TIMEOUT_SECONDS);
        assertEquals(60, ClaudeConfig.DEFAULT_IMPLEMENTATION_MAX_TURNS,
                "implementation's own turn budget must stay exactly as it was");
        assertEquals(900, ClaudeConfig.DEFAULT_IMPLEMENTATION_TIMEOUT_SECONDS);
        assertEquals(25, ClaudeConfig.DEFAULT_HUMAN_REVIEW_MAX_TURNS,
                "human review's own turn budget must stay exactly as it was");
        assertEquals(360, ClaudeConfig.DEFAULT_HUMAN_REVIEW_TIMEOUT_SECONDS,
                "human review's own timeout must stay exactly as it was");
        assertEquals(8, ClaudeConfig.DEFAULT_ANALYSIS_FINALIZATION_MAX_TURNS,
                "analysis finalization's own turn budget must stay exactly as it was");
        assertEquals(8, ClaudeConfig.DEFAULT_IMPLEMENTATION_FINALIZATION_MAX_TURNS,
                "implementation finalization's own turn budget must stay exactly as it was");
        assertEquals(8, ClaudeConfig.DEFAULT_HUMAN_REVIEW_FINALIZATION_MAX_TURNS,
                "human review finalization's own turn budget must stay exactly as it was");
        assertEquals(1800, ClaudeConfig.DEFAULT_TIMEOUT_SECONDS,
                "the shared timeout every finalization call runs under must stay exactly as it was");
    }

    @Test
    @DisplayName("a blank model falls back to opus rather than passing an empty --model")
    void blankModelFallsBackToOpus() {
        assertEquals("opus", ClaudeConfig.fromEnvironment(Map.of(ClaudeConfig.CLAUDE_MODEL, "   ")).model());
    }

    @Test
    @DisplayName("surrounding whitespace is stripped from the model and executable")
    void whitespaceIsStripped() {
        ClaudeConfig config = ClaudeConfig.fromEnvironment(Map.of(
                ClaudeConfig.CLAUDE_MODEL, "  opus  ",
                ClaudeConfig.CLAUDE_EXECUTABLE, "  claude  "));

        assertEquals("opus", config.model());
        assertEquals("claude", config.executable());
    }

    @Test
    @DisplayName("a non-numeric max turns is rejected rather than silently ignored")
    void nonNumericMaxTurnsIsRejected() {
        ConfigurationException e = assertThrows(ConfigurationException.class, () ->
                ClaudeConfig.fromEnvironment(Map.of(ClaudeConfig.CLAUDE_MAX_TURNS, "many")));
        assertEquals(true, e.getMessage().contains(ClaudeConfig.CLAUDE_MAX_TURNS));
    }

    @Test
    @DisplayName("a zero or negative max turns is rejected")
    void nonPositiveMaxTurnsIsRejected() {
        assertThrows(ConfigurationException.class, () ->
                ClaudeConfig.fromEnvironment(Map.of(ClaudeConfig.CLAUDE_MAX_TURNS, "0")));
        assertThrows(ConfigurationException.class, () ->
                ClaudeConfig.fromEnvironment(Map.of(ClaudeConfig.CLAUDE_MAX_TURNS, "-5")));
    }

    @Test
    @DisplayName("a zero or negative timeout is rejected, since it would kill every run instantly")
    void nonPositiveTimeoutIsRejected() {
        assertThrows(ConfigurationException.class, () ->
                ClaudeConfig.fromEnvironment(Map.of(ClaudeConfig.CLAUDE_TIMEOUT_SECONDS, "0")));
    }

    // ---- Human Review Engineer's own budget ------------------------------------------------------

    @Test
    @DisplayName("Human Review's turn budget, timeout and finalization budget are all configurable on their own")
    void humanReviewBudgetIsConfigurableOnItsOwn() {
        ClaudeConfig config = ClaudeConfig.fromEnvironment(Map.of(
                ClaudeConfig.CLAUDE_HUMAN_REVIEW_MAX_TURNS, "12",
                ClaudeConfig.CLAUDE_HUMAN_REVIEW_TIMEOUT_SECONDS, "150",
                ClaudeConfig.CLAUDE_HUMAN_REVIEW_FINALIZATION_MAX_TURNS, "5"));

        assertEquals(12, config.humanReviewMaxTurns());
        assertEquals(Duration.ofSeconds(150), config.humanReviewTimeout());
        assertEquals(5, config.humanReviewFinalizationMaxTurns());
        assertEquals(12, config.maxTurnsFor(ClaudePhase.HUMAN_REVIEW));
        assertEquals(Duration.ofSeconds(150), config.timeoutFor(ClaudePhase.HUMAN_REVIEW));
        assertEquals(ClaudeConfig.DEFAULT_ANALYSIS_MAX_TURNS, config.analysisMaxTurns(),
                "an override to Human Review's budget must not affect analysis's own");
        assertEquals(ClaudeConfig.DEFAULT_IMPLEMENTATION_MAX_TURNS, config.implementationMaxTurns(),
                "an override to Human Review's budget must not affect implementation's own");
    }

    @Test
    @DisplayName("Human Review's defaults match its own documented placeholders")
    void humanReviewDefaults() {
        ClaudeConfig config = ClaudeConfig.fromEnvironment(Map.of());

        assertEquals(ClaudeConfig.DEFAULT_HUMAN_REVIEW_MAX_TURNS, config.humanReviewMaxTurns());
        assertEquals(Duration.ofSeconds(ClaudeConfig.DEFAULT_HUMAN_REVIEW_TIMEOUT_SECONDS),
                config.humanReviewTimeout());
        assertEquals(ClaudeConfig.DEFAULT_HUMAN_REVIEW_FINALIZATION_MAX_TURNS,
                config.humanReviewFinalizationMaxTurns());
    }
}
