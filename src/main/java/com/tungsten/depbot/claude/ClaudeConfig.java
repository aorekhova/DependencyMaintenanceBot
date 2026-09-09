package com.tungsten.depbot.claude;

import com.tungsten.depbot.config.ConfigurationException;

import java.time.Duration;
import java.util.Map;

/**
 * How to invoke Claude Code, read from the process environment.
 *
 * <p><strong>The model is never chosen automatically and never downgraded.</strong> It defaults to
 * {@value #DEFAULT_MODEL} -- an alias that always resolves to the current most capable Opus model,
 * so this application does not have to track model IDs as they change. If the configured model is
 * unavailable to the account, the affected unit fails and says so; nothing here substitutes a
 * cheaper or weaker model, because silently producing a lower-quality dependency upgrade is worse
 * than producing none and reporting why.
 *
 * <p>Setting {@link #CLAUDE_MODEL} to something else is allowed -- that is a deliberate operator
 * choice, which is a different thing from an automatic fallback.
 *
 * <p>{@code maxTurns} is the shared, general-purpose turn limit -- kept for {@link ClaudeCommand}'s
 * two-arg {@code build(config, policy)} overload and as the base every convenience constructor
 * defaults from. Each of the three Claude roles has its own budget: {@link #analysisMaxTurns}
 * (the Vulnerability Analysis Engineer's one whole-batch call), {@link #implementationMaxTurns} (the
 * Remediation Engineer) and {@link #humanReviewMaxTurns} (the Human Review Engineer), selected by
 * {@link #maxTurnsFor}. Each finalization budget is smaller still on purpose -- the short, tool-free or
 * read-only call that writes up a result which ran out of investigation room, never a second attempt at
 * the work itself.
 *
 * <p>{@code timeout} is the shared, general-purpose wall-clock limit -- kept as the base every
 * convenience constructor defaults from, and as the timeout every finalization call still uses
 * unmodified (they are short by construction, through their own turn budgets, not through a phase
 * timeout of their own). Each role has its own, deliberately smaller wall-clock cap, selected by
 * {@link #timeoutFor}.
 *
 * <p><strong>{@link #analysisMaxTurns}/{@link #analysisTimeout}/{@link #analysisFinalizationMaxTurns}
 * are placeholders, not calibrated production defaults.</strong> The Vulnerability Analysis Engineer now
 * covers every finding in a run in one call, rather than one finding at a time, and how large a budget
 * that genuinely needs scales with how many findings a real batch actually contains -- something this
 * codebase has no measurement of yet. The values here keep the mechanism (and its tests) meaningful;
 * they are expected to be revised once a real batch pilot shows what they should actually be, not
 * treated as validated the way {@link #DEFAULT_IMPLEMENTATION_MAX_TURNS} and its timeout now are.
 */
public record ClaudeConfig(
        String executable, String model, int maxTurns,
        int analysisMaxTurns, int implementationMaxTurns, int humanReviewMaxTurns,
        int analysisFinalizationMaxTurns, int implementationFinalizationMaxTurns,
        int humanReviewFinalizationMaxTurns,
        Duration timeout, Duration analysisTimeout, Duration implementationTimeout,
        Duration humanReviewTimeout,
        int analysisSecondAttemptMaxTurns, Duration analysisSecondAttemptTimeout) {

    public static final String CLAUDE_EXECUTABLE = "CLAUDE_EXECUTABLE";
    public static final String CLAUDE_MODEL = "CLAUDE_MODEL";
    public static final String CLAUDE_MAX_TURNS = "CLAUDE_MAX_TURNS";
    public static final String CLAUDE_ANALYSIS_MAX_TURNS = "CLAUDE_ANALYSIS_MAX_TURNS";
    public static final String CLAUDE_IMPLEMENTATION_MAX_TURNS = "CLAUDE_IMPLEMENTATION_MAX_TURNS";
    public static final String CLAUDE_HUMAN_REVIEW_MAX_TURNS = "CLAUDE_HUMAN_REVIEW_MAX_TURNS";
    public static final String CLAUDE_ANALYSIS_FINALIZATION_MAX_TURNS =
            "CLAUDE_ANALYSIS_FINALIZATION_MAX_TURNS";
    public static final String CLAUDE_IMPLEMENTATION_FINALIZATION_MAX_TURNS =
            "CLAUDE_IMPLEMENTATION_FINALIZATION_MAX_TURNS";
    public static final String CLAUDE_HUMAN_REVIEW_FINALIZATION_MAX_TURNS =
            "CLAUDE_HUMAN_REVIEW_FINALIZATION_MAX_TURNS";
    public static final String CLAUDE_TIMEOUT_SECONDS = "CLAUDE_TIMEOUT_SECONDS";
    public static final String CLAUDE_ANALYSIS_TIMEOUT_SECONDS = "CLAUDE_ANALYSIS_TIMEOUT_SECONDS";
    public static final String CLAUDE_IMPLEMENTATION_TIMEOUT_SECONDS =
            "CLAUDE_IMPLEMENTATION_TIMEOUT_SECONDS";
    public static final String CLAUDE_HUMAN_REVIEW_TIMEOUT_SECONDS = "CLAUDE_HUMAN_REVIEW_TIMEOUT_SECONDS";
    public static final String CLAUDE_ANALYSIS_SECOND_ATTEMPT_MAX_TURNS =
            "CLAUDE_ANALYSIS_SECOND_ATTEMPT_MAX_TURNS";
    public static final String CLAUDE_ANALYSIS_SECOND_ATTEMPT_TIMEOUT_SECONDS =
            "CLAUDE_ANALYSIS_SECOND_ATTEMPT_TIMEOUT_SECONDS";

    public static final String DEFAULT_EXECUTABLE = "claude";
    public static final String DEFAULT_MODEL = "opus";
    public static final int DEFAULT_MAX_TURNS = 30;
    /**
     * Placeholder -- see the class javadoc. Larger than the old per-finding
     * {@code DEFAULT_ASSESSMENT_MAX_TURNS} (25) since one call now covers every finding in the batch, not
     * one; not yet informed by any real multi-finding batch run. Raised from {@code 60} to {@code 100}
     * after a real batch run showed the primary call needing more room than 60 turns gave it, well
     * before its wall-clock budget was actually exhausted.
     */
    public static final int DEFAULT_ANALYSIS_MAX_TURNS = 100;
    /**
     * A real pilot spent over 8 minutes investigating a single library before this budget (then 60) and
     * the shared 30-minute timeout let it run that long. Cut down deliberately, together with
     * {@link #DEFAULT_IMPLEMENTATION_TIMEOUT_SECONDS}: the goal is a sufficient engineering conclusion in
     * bounded time, not maximum investigation depth.
     */
    public static final int DEFAULT_IMPLEMENTATION_MAX_TURNS = 60;
    /** Same order of magnitude as {@link #DEFAULT_ANALYSIS_MAX_TURNS} -- also a placeholder. */
    public static final int DEFAULT_HUMAN_REVIEW_MAX_TURNS = 25;
    /**
     * Enough for Claude to write one JSON conclusion, and to recover from one malformed attempt at it,
     * with no tool calls to spend any of it on. Not a budget for investigating anything -- if it is not
     * enough turns to state a conclusion at all, the honest answer is {@code INCONCLUSIVE}, not more turns.
     */
    public static final int DEFAULT_ANALYSIS_FINALIZATION_MAX_TURNS = 8;
    /**
     * Now tool-free like the other two finalizations ({@link ClaudeToolPolicy#forImplementationFinalization()})
     * -- the evidence (git status/diff/diffstat) is fully precomputed by Java and embedded in the prompt,
     * so there is nothing left to spend a tool-call turn on. Enough to write one JSON conclusion and
     * recover from one malformed attempt at it, same as {@link #DEFAULT_ANALYSIS_FINALIZATION_MAX_TURNS}.
     * Previously {@code 10}, sized for a read-only call that needed a turn or two for its own
     * {@code git diff}/{@code git status} -- that reason no longer applies, so this is a decrease, not
     * the "just raise max-turns" fix a real production {@code error_max_turns} failure might otherwise
     * suggest: the budget shrinks because the tool calls that used to need it are gone.
     */
    public static final int DEFAULT_IMPLEMENTATION_FINALIZATION_MAX_TURNS = 8;
    /** Tool-free, same reasoning as {@link #DEFAULT_ANALYSIS_FINALIZATION_MAX_TURNS}. */
    public static final int DEFAULT_HUMAN_REVIEW_FINALIZATION_MAX_TURNS = 8;
    public static final int DEFAULT_TIMEOUT_SECONDS = 1800;
    /**
     * Thirty minutes. Placeholder -- see the class javadoc. Larger than the old per-finding
     * {@code DEFAULT_ASSESSMENT_TIMEOUT_SECONDS} (360, six minutes) since one call now covers every
     * finding in the batch. Raised from {@code 900} (fifteen minutes) after a real batch run showed the
     * primary call being cut off by this wall-clock cap rather than by its own turn budget -- matches
     * {@link #DEFAULT_TIMEOUT_SECONDS}, the shared default every finalization call already runs under.
     */
    public static final int DEFAULT_ANALYSIS_TIMEOUT_SECONDS = 1800;
    /**
     * Fifteen minutes. A real pilot's implementation call ran 16m17s before this cap existed -- a
     * remediation still needs more wall-clock room than an analysis (editing files, re-checking its
     * own work), but not the full 30-minute shared default, especially now that a timeout gets a
     * report-only finalization rather than an instant rollback. Raised from {@code 480} (eight minutes)
     * after a real BouncyCastle remediation was cut off by this wall-clock cap -- {@code maxTurnsExceeded}
     * was {@code false}, so the call was still doing genuine work, not stuck -- whereas an earlier,
     * otherwise-identical successful run of the same library had completed cleanly in 3m49s: eight
     * minutes was too tight a margin above a call that can legitimately vary that much run to run.
     */
    public static final int DEFAULT_IMPLEMENTATION_TIMEOUT_SECONDS = 900;
    /** Same order of magnitude as {@link #DEFAULT_ANALYSIS_TIMEOUT_SECONDS} -- also a placeholder. */
    public static final int DEFAULT_HUMAN_REVIEW_TIMEOUT_SECONDS = 360;
    /**
     * Half of {@link #DEFAULT_ANALYSIS_MAX_TURNS} -- the turn budget for the <em>second</em> Vulnerability
     * Analysis attempt, run only when the first ran out of turns or time (see
     * {@code BatchAnalysisService}'s two-attempt scheme). Deliberately still a real investigation budget,
     * not a finalization-sized one: this attempt keeps the same tools as the first and is expected to
     * continue investigating, usually with the first attempt's own session resumed, not merely write up
     * whatever the first already knew.
     */
    public static final int DEFAULT_ANALYSIS_SECOND_ATTEMPT_MAX_TURNS = 50;
    /** Half of {@link #DEFAULT_ANALYSIS_TIMEOUT_SECONDS} -- same reasoning as {@link
     * #DEFAULT_ANALYSIS_SECOND_ATTEMPT_MAX_TURNS}. */
    public static final int DEFAULT_ANALYSIS_SECOND_ATTEMPT_TIMEOUT_SECONDS = 900;

    /**
     * A config with no reason to give any role its own turn budget or timeout -- most call sites,
     * including every existing test. Every role and every finalization call still gets its own
     * {@code DEFAULT_*} value, regardless of {@code maxTurns}/{@code timeout} here; those defaults are
     * deliberately their own values, not copies of the shared ones.
     */
    public ClaudeConfig(String executable, String model, int maxTurns, Duration timeout) {
        this(executable, model, maxTurns,
                DEFAULT_ANALYSIS_MAX_TURNS, DEFAULT_IMPLEMENTATION_MAX_TURNS, DEFAULT_HUMAN_REVIEW_MAX_TURNS,
                DEFAULT_ANALYSIS_FINALIZATION_MAX_TURNS, DEFAULT_IMPLEMENTATION_FINALIZATION_MAX_TURNS,
                DEFAULT_HUMAN_REVIEW_FINALIZATION_MAX_TURNS,
                timeout, Duration.ofSeconds(DEFAULT_ANALYSIS_TIMEOUT_SECONDS),
                Duration.ofSeconds(DEFAULT_IMPLEMENTATION_TIMEOUT_SECONDS),
                Duration.ofSeconds(DEFAULT_HUMAN_REVIEW_TIMEOUT_SECONDS),
                DEFAULT_ANALYSIS_SECOND_ATTEMPT_MAX_TURNS,
                Duration.ofSeconds(DEFAULT_ANALYSIS_SECOND_ATTEMPT_TIMEOUT_SECONDS));
    }

    /** Reads the configuration from the real process environment. */
    public static ClaudeConfig fromEnvironment() {
        return fromEnvironment(System.getenv());
    }

    /**
     * Reads the configuration from the supplied map.
     *
     * <p>Public so tests can inject values without mutating {@code System.getenv()}, which cannot
     * be changed reliably from within a JVM.
     */
    public static ClaudeConfig fromEnvironment(Map<String, String> environment) {
        return new ClaudeConfig(
                text(environment, CLAUDE_EXECUTABLE, DEFAULT_EXECUTABLE),
                text(environment, CLAUDE_MODEL, DEFAULT_MODEL),
                positiveInt(environment, CLAUDE_MAX_TURNS, DEFAULT_MAX_TURNS),
                positiveInt(environment, CLAUDE_ANALYSIS_MAX_TURNS, DEFAULT_ANALYSIS_MAX_TURNS),
                positiveInt(environment, CLAUDE_IMPLEMENTATION_MAX_TURNS, DEFAULT_IMPLEMENTATION_MAX_TURNS),
                positiveInt(environment, CLAUDE_HUMAN_REVIEW_MAX_TURNS, DEFAULT_HUMAN_REVIEW_MAX_TURNS),
                positiveInt(environment, CLAUDE_ANALYSIS_FINALIZATION_MAX_TURNS,
                        DEFAULT_ANALYSIS_FINALIZATION_MAX_TURNS),
                positiveInt(environment, CLAUDE_IMPLEMENTATION_FINALIZATION_MAX_TURNS,
                        DEFAULT_IMPLEMENTATION_FINALIZATION_MAX_TURNS),
                positiveInt(environment, CLAUDE_HUMAN_REVIEW_FINALIZATION_MAX_TURNS,
                        DEFAULT_HUMAN_REVIEW_FINALIZATION_MAX_TURNS),
                Duration.ofSeconds(positiveInt(environment, CLAUDE_TIMEOUT_SECONDS, DEFAULT_TIMEOUT_SECONDS)),
                Duration.ofSeconds(positiveInt(environment, CLAUDE_ANALYSIS_TIMEOUT_SECONDS,
                        DEFAULT_ANALYSIS_TIMEOUT_SECONDS)),
                Duration.ofSeconds(positiveInt(environment, CLAUDE_IMPLEMENTATION_TIMEOUT_SECONDS,
                        DEFAULT_IMPLEMENTATION_TIMEOUT_SECONDS)),
                Duration.ofSeconds(positiveInt(environment, CLAUDE_HUMAN_REVIEW_TIMEOUT_SECONDS,
                        DEFAULT_HUMAN_REVIEW_TIMEOUT_SECONDS)),
                positiveInt(environment, CLAUDE_ANALYSIS_SECOND_ATTEMPT_MAX_TURNS,
                        DEFAULT_ANALYSIS_SECOND_ATTEMPT_MAX_TURNS),
                Duration.ofSeconds(positiveInt(environment, CLAUDE_ANALYSIS_SECOND_ATTEMPT_TIMEOUT_SECONDS,
                        DEFAULT_ANALYSIS_SECOND_ATTEMPT_TIMEOUT_SECONDS)));
    }

    /** The turn budget for {@code phase} -- every phase has its own; there is no shared fallback. */
    public int maxTurnsFor(ClaudePhase phase) {
        return switch (phase) {
            case ASSESSMENT -> analysisMaxTurns;
            case IMPLEMENTATION -> implementationMaxTurns;
            case HUMAN_REVIEW -> humanReviewMaxTurns;
        };
    }

    /**
     * The wall-clock timeout for {@code phase} -- every phase has its own; there is no shared
     * fallback, the same as {@link #maxTurnsFor}.
     */
    public Duration timeoutFor(ClaudePhase phase) {
        return switch (phase) {
            case ASSESSMENT -> analysisTimeout;
            case IMPLEMENTATION -> implementationTimeout;
            case HUMAN_REVIEW -> humanReviewTimeout;
        };
    }

    private static String text(Map<String, String> environment, String name, String fallback) {
        String value = environment == null ? null : environment.get(name);
        return (value == null || value.isBlank()) ? fallback : value.strip();
    }

    private static int positiveInt(Map<String, String> environment, String name, int fallback) {
        String value = environment == null ? null : environment.get(name);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        int parsed;
        try {
            parsed = Integer.parseInt(value.strip());
        } catch (NumberFormatException e) {
            throw new ConfigurationException(name + " must be a whole number, but was: " + value.strip());
        }
        if (parsed <= 0) {
            throw new ConfigurationException(name + " must be greater than zero, but was: " + parsed);
        }
        return parsed;
    }
}
