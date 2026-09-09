package com.tungsten.depbot.claude;

/**
 * Which of the three Claude roles a remediation run calls on.
 *
 * <p>Every run makes exactly one {@link #ASSESSMENT} call -- the Vulnerability Analysis Engineer --
 * which sees every Mend finding in the run at once, investigates freely, and reports both its
 * per-finding conclusions and the remediation groups it decided are needed. Each group that call
 * explicitly allowed for automation then gets one {@link #IMPLEMENTATION} call -- the Remediation
 * Engineer -- which carries out its own plan on the shared branch the orchestrator prepared for it.
 * Every other group or finding -- flagged for human review, blocked, inconclusive, or reached by an
 * analysis that failed outright -- gets one read-only {@link #HUMAN_REVIEW} call instead: the Human
 * Review Engineer, which only writes up a report and never changes anything.
 *
 * <p>The phase is <em>not</em> a process-level concern -- {@link ClaudeProcessRunner} never sees it.
 * It selects which {@link ClaudeToolPolicy} the invocation runs under, names the subdirectory the
 * attempt's artifacts are written to, and appears as {@link #promptMarker()} at the top of the
 * prompt so a saved {@code prompt.md} states on its own which call produced it.
 */
public enum ClaudePhase {

    ASSESSMENT("assessment"),
    IMPLEMENTATION("implementation"),
    HUMAN_REVIEW("human-review");

    /** The literal every phase marker starts with, so one search finds a marker of any phase. */
    public static final String MARKER_PREFIX = "depbot-phase:";

    private final String directoryName;

    ClaudePhase(String directoryName) {
        this.directoryName = directoryName;
    }

    /** The subdirectory this phase's artifacts belong in, under a unit's directory. */
    public String directoryName() {
        return directoryName;
    }

    /**
     * A one-line, machine-readable declaration of the phase, written as the first line of the
     * prompt.
     *
     * <p>Formatted as an HTML comment so it is inert in the Markdown prompt Claude reads, while
     * still being a plain literal anything reading the artifact afterwards can search for. No
     * phase's marker is a substring of another's.
     */
    public String promptMarker() {
        return "<!-- " + MARKER_PREFIX + " " + name() + " -->";
    }
}
