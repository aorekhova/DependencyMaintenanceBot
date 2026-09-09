package com.tungsten.depbot.claude;

/**
 * Runs one Claude Code invocation and reports whether the process itself finished cleanly.
 *
 * <p>The single seam all three roles share. An implementation is responsible for process execution and
 * nothing else: the command line, the working directory, the prompt on standard input, the captured
 * streams, the timeout and its cleanup, the exit code, and the artifacts recording all of that. It
 * has no opinion on what Claude was asked or whether the answer is any good -- interpreting an
 * analysis's JSON, applying the impact-score policy, checking a diff and deciding
 * commit-versus-rollback all belong above this interface, in
 * {@code BatchAnalysisService}, {@code RemediationImplementationService} and {@code HumanReviewService}.
 *
 * <p>Exists as an interface so those services can be tested against a stub without a process, while
 * the tests that need to prove the real command line and permissions are what reach the operating
 * system run {@link ClaudeCodeExecutor} against a fake executable instead.
 */
public interface ClaudeInvoker {

    /**
     * @return what the process did -- never {@code null}, and never an exception for an ordinary
     *         failure: a missing executable, a non-zero exit and a timeout are all reported as an
     *         outcome, because each is a normal thing to record about an attempt rather than a
     *         defect in the caller
     */
    ClaudeRunOutcome run(ClaudeRunRequest request);
}
