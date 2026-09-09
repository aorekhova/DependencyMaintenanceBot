package com.tungsten.depbot.claude;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The exact tool permissions one Claude invocation runs under: what it may use, and what it is
 * explicitly refused.
 *
 * <p>All three roles share one developer environment and differ only in editing: {@link #forAssessment()}
 * and {@link #forHumanReview()} cannot change anything, {@link #forImplementation()} can. None is built
 * from a curated list of
 * individually pre-approved commands. A real pilot ran into exactly the failure mode that a narrow
 * allow-list produces: Claude repeatedly asked for shell commands, dependency tooling, and network
 * access this application had never anticipated needing to name, burned its turn budget on permission
 * denials, and never reached a usable answer. A senior developer investigating or fixing a dependency
 * finding needs an ordinary developer environment -- Maven, Java, a shell, {@code curl}, package
 * inspection tools, web search, and git -- not a menu of pre-approved verbs.
 *
 * <p><strong>Git is fully available locally, fetch and remote inspection included.</strong> {@code log},
 * {@code show}, {@code diff}, {@code grep}, {@code blame}, {@code for-each-ref}, {@code fetch},
 * {@code remote}, {@code checkout}, {@code switch}, {@code branch}, {@code reset}, {@code restore},
 * {@code commit} and every other operation that does not itself mutate a remote are simply available,
 * the same way {@code Bash} makes Maven or {@code curl} available -- there is no curated allow-list of
 * individual git subcommands to keep in sync. The boundary is exactly, and only, publishing:
 * {@link #FORBIDDEN_GIT_PUBLISHING} refuses {@code git push} -- the one git subcommand that writes
 * anything to a remote -- because publishing is never Claude's to do. {@code fetch} and {@code remote}
 * read from or reconfigure only this local checkout; they do not mutate anything remote, and this
 * application no longer refuses them on the strength of an orchestration convention that was never a
 * security boundary to begin with (see {@code RemediationCheckoutManager#enforceOriginalState}, which is
 * what actually keeps the shared checkout consistent now, regardless of what Claude does to it).
 *
 * <p>Nothing here assumes Claude leaves git or the working tree the way the prompt asks it to. What a
 * phase is asked to do with this access (an assessment must not disturb the shared checkout; an
 * implementation's finished change is still staged and committed by the bot, not by Claude) is asked of
 * it in the prompt, but the orchestrator never trusts that the request was honoured -- it independently
 * re-establishes its own invariants after every phase instead.
 *
 * <p>No profile passes {@code --dangerously-skip-permissions} -- the point of running an agent
 * unattended against a real repository is that the permission system stays on; widening what it allows
 * is not the same as turning it off.
 */
public record ClaudeToolPolicy(List<String> allowedTools, List<String> disallowedTools) {

    /**
     * The developer environment both phases run in: an unrestricted shell (so Maven, Java, package
     * managers, {@code curl}, archive tools, git and anything else a real investigation or fix needs are
     * all simply available, the way they would be to a developer at a terminal), file reading and
     * searching, and web search/fetch for looking up an advisory, a release note or a compatibility
     * question.
     */
    public static final List<String> DEVELOPER_ACCESS =
            List.of("Bash", "Read", "Glob", "Grep", "WebSearch", "WebFetch");

    /**
     * The only git this application ever refuses Claude at the tool level: {@code push} (and
     * force-push, and a remote branch or tag's deletion, which are the same subcommand with different
     * arguments) -- the one thing that writes anything to a remote. Publishing is never Claude's to do:
     * nothing in this application pushes, opens a merge request, or mutates anything on a git host, and
     * Claude does not get to be the exception. Every other git subcommand, {@code fetch} and
     * {@code remote} included, only reads from or reconfigures this local checkout and is not refused.
     */
    public static final List<String> FORBIDDEN_GIT_PUBLISHING = List.of("Bash(git push:*)");

    /** The file-editing tools, granted to {@link #forImplementation()} only. */
    public static final List<String> EDITING = List.of("Edit", "Write", "MultiEdit");

    public ClaudeToolPolicy {
        Objects.requireNonNull(allowedTools, "allowedTools");
        Objects.requireNonNull(disallowedTools, "disallowedTools");
        allowedTools = List.copyOf(allowedTools);
        disallowedTools = List.copyOf(disallowedTools);
    }

    /** The profile for {@code phase}. */
    public static ClaudeToolPolicy forPhase(ClaudePhase phase) {
        Objects.requireNonNull(phase, "phase");
        return switch (phase) {
            case ASSESSMENT -> forAssessment();
            case IMPLEMENTATION -> forImplementation();
            case HUMAN_REVIEW -> forHumanReview();
        };
    }

    /**
     * The full developer environment, full local git, publishing refused, and no way to change any
     * file.
     *
     * <p>The editing tools are both absent from the allow-list and named in the disallow-list. An
     * assessment that quietly edited a file would put a change on whatever branch happened to be
     * checked out, before any remediation branch for it even exists. Git write operations that move or
     * commit on the shared checkout are technically available here the same way they are for the
     * implementation phase; the prompt is what tells an assessment not to use them, since a tool
     * permission cannot distinguish "investigate history" from "switch the branch everyone else depends
     * on" the way a plain-language instruction can.
     */
    public static ClaudeToolPolicy forAssessment() {
        List<String> disallowed = new ArrayList<>(FORBIDDEN_GIT_PUBLISHING);
        disallowed.addAll(EDITING);
        return new ClaudeToolPolicy(DEVELOPER_ACCESS, disallowed);
    }

    /**
     * The full developer environment, full local git, publishing refused, and editing allowed.
     *
     * <p>There is deliberately no restriction here on <em>which</em> files may be edited: which files a
     * remediation genuinely needs to touch -- a POM, a BOM or a version property, Java sources, tests,
     * resources, configuration, generated third-party metadata, a related dependency in the same family
     * -- is a judgement the implementation makes from its own plan, not something a tool permission can
     * usefully predict. What the change is allowed to be is enforced afterwards, on the resulting diff,
     * by {@code RemediationDiffPolicy} before anything is committed.
     */
    public static ClaudeToolPolicy forImplementation() {
        List<String> allowed = new ArrayList<>(DEVELOPER_ACCESS);
        allowed.addAll(EDITING);
        return new ClaudeToolPolicy(allowed, FORBIDDEN_GIT_PUBLISHING);
    }

    /**
     * No tools at all. Used only for the short, report-only finalization call that follows an
     * assessment which ran out of turns or time: there must be no way for that call to keep
     * investigating, since it is asked only to write down what was already established.
     */
    public static ClaudeToolPolicy forAssessmentFinalization() {
        List<String> disallowed = new ArrayList<>(DEVELOPER_ACCESS);
        disallowed.addAll(EDITING);
        return new ClaudeToolPolicy(List.of(), disallowed);
    }

    /**
     * No tools at all. Used only for the short, report-only finalization call that follows an
     * implementation which ran out of turns or time -- previously the only finalization policy that
     * granted any tools at all (read-only developer access, for {@code git diff}/{@code git status}),
     * which is exactly what let a real production finalization call burn its entire turn budget on tool
     * calls and never emit a report. Java now precomputes every fact this call could have looked up
     * (see {@code RemediationImplementationService#finalizeImplementation}) and embeds it in the prompt,
     * so there is nothing left for a tool to do here -- matching {@link #forAssessmentFinalization()}'s
     * own reasoning exactly.
     */
    public static ClaudeToolPolicy forImplementationFinalization() {
        List<String> disallowed = new ArrayList<>(DEVELOPER_ACCESS);
        disallowed.addAll(EDITING);
        return new ClaudeToolPolicy(List.of(), disallowed);
    }

    /**
     * Read-only, full developer environment, publishing refused, editing refused. Used for the Human
     * Review Engineer: it may investigate as freely as it needs to answer the report's fixed questions --
     * reading files, running a build, checking history -- but it never edits anything and never commits,
     * because writing a report is the whole of its job.
     */
    public static ClaudeToolPolicy forHumanReview() {
        List<String> disallowed = new ArrayList<>(FORBIDDEN_GIT_PUBLISHING);
        disallowed.addAll(EDITING);
        return new ClaudeToolPolicy(DEVELOPER_ACCESS, disallowed);
    }

    /**
     * No tools at all. Used only for the short, report-only finalization call that follows a Human
     * Review Engineer call which ran out of turns or time. Unlike
     * {@link #forImplementationFinalization()}, there is no "what's actually on disk" fact this call
     * needs a tool to see -- Human Review never edits anything in the first place, so by the time
     * finalization is reached the job is purely to write up what the primary call (or its own bounded
     * follow-up investigation) already established, exactly the reasoning behind
     * {@link #forAssessmentFinalization()}.
     */
    public static ClaudeToolPolicy forHumanReviewFinalization() {
        List<String> disallowed = new ArrayList<>(DEVELOPER_ACCESS);
        disallowed.addAll(EDITING);
        return new ClaudeToolPolicy(List.of(), disallowed);
    }

    /** The comma-separated form the {@code --allowedTools} flag takes. */
    public String allowedArgument() {
        return String.join(",", allowedTools);
    }

    /** The comma-separated form the {@code --disallowedTools} flag takes. */
    public String disallowedArgument() {
        return String.join(",", disallowedTools);
    }

    public boolean permitsEditing() {
        return allowedTools.stream().anyMatch(EDITING::contains);
    }
}
