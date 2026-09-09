package com.tungsten.depbot.jenkins;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * An in-memory stand-in for the real Jenkins Remote API, so tests exercise
 * {@link JenkinsValidationService}'s own orchestration/idempotency logic without ever reaching a
 * network. Never used by production code -- test-support only.
 */
public final class FakeJenkinsClient implements JenkinsClient {

    private final List<JenkinsCandidate> triggeredCandidates = new ArrayList<>();
    private JenkinsBuildResult cannedResult = new JenkinsBuildResult(
            JenkinsValidationStatus.SUCCESS, 1, "https://jenkins.example.invalid/job/x/1/", 1000L,
            "Jenkins reported result SUCCESS");
    private final Map<Integer, JenkinsBuildResult> resultsByCallNumber = new HashMap<>();
    private int callCount = 0;
    private int callNumberToFail = -1;
    private RuntimeException failureException;
    private int nextQueueId = 1;
    private int waitForCompletionCount = 0;
    private String cannedConsoleLog = "Build log unavailable in this test.";
    private int fetchConsoleLogCount = 0;

    /** Every subsequent {@link #waitForCompletion} call returns this result, until changed again. */
    public void respondWith(JenkinsBuildResult result) {
        this.cannedResult = result;
    }

    /**
     * The {@code callNumber}-th call this fake receives, counting {@link #triggerBuild} and
     * {@link #waitForCompletion} together starting at 1 -- the same counter {@link #failOnCallNumber}
     * uses -- returns {@code result} from {@link #waitForCompletion} instead of the default canned one.
     * Lets a test give one specific Jenkins validation attempt (e.g. a cohort's final integration gate)
     * a different result from every other attempt in the same run.
     */
    public void respondOnCallNumber(int callNumber, JenkinsBuildResult result) {
        resultsByCallNumber.put(callNumber, result);
    }

    /**
     * The {@code callNumber}-th call this fake receives, counting {@link #triggerBuild} and
     * {@link #waitForCompletion} together starting at 1, throws {@code exception} instead of acting.
     */
    public void failOnCallNumber(int callNumber, RuntimeException exception) {
        this.callNumberToFail = callNumber;
        this.failureException = exception;
    }

    private void maybeFail() {
        callCount++;
        if (callCount == callNumberToFail) {
            callNumberToFail = -1;
            throw failureException;
        }
    }

    @Override
    public JenkinsBuildRef triggerBuild(JenkinsCandidate candidate) {
        maybeFail();
        triggeredCandidates.add(candidate);
        return JenkinsBuildRef.queueItem("https://jenkins.example.invalid/queue/item/" + nextQueueId++ + "/");
    }

    @Override
    public JenkinsBuildResult waitForCompletion(
            JenkinsBuildRef ref, Duration timeout, Duration pollInterval, Runnable heartbeat) {
        maybeFail();
        waitForCompletionCount++;
        if (heartbeat != null) {
            heartbeat.run();
        }
        JenkinsBuildResult override = resultsByCallNumber.get(callCount);
        return override != null ? override : cannedResult;
    }

    /** Every subsequent {@link #fetchConsoleLog} call returns this text, until changed again. */
    public void respondToConsoleLogWith(String consoleLog) {
        this.cannedConsoleLog = consoleLog;
    }

    @Override
    public String fetchConsoleLog(int buildNumber) {
        fetchConsoleLogCount++;
        return cannedConsoleLog;
    }

    public int fetchConsoleLogCount() {
        return fetchConsoleLogCount;
    }

    // ---- test inspection ---------------------------------------------------------------------------

    public int triggerCount() {
        return triggeredCandidates.size();
    }

    public int waitForCompletionCount() {
        return waitForCompletionCount;
    }

    public List<JenkinsCandidate> triggeredCandidates() {
        return List.copyOf(triggeredCandidates);
    }

    public JenkinsCandidate lastTriggeredCandidate() {
        return triggeredCandidates.get(triggeredCandidates.size() - 1);
    }
}
