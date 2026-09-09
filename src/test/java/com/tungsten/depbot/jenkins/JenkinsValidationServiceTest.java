package com.tungsten.depbot.jenkins;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.git.GitTestRepos;
import com.tungsten.depbot.run.RemediationRunService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JenkinsValidationServiceTest {

    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-08-20T10:00:00Z"), ZoneOffset.UTC);
    private static final String RUN_ID = "run1";
    private static final String UNIT_ID = "critical__org.example__lib";

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();
    private final JsonMapper mapper = JsonMapper.builder().build();
    private Path repo;
    private String baselineSha;
    private String candidateSha;
    private RemediationRunService runService;

    @BeforeEach
    void createRepository() throws IOException, InterruptedException {
        repo = GitTestRepos.createOriginAndClone(tempDir);
        baselineSha = GitTestRepos.shaOf(repo, "HEAD");
        Files.writeString(repo.resolve("file.txt"), "hello, changed\n", StandardCharsets.UTF_8);
        GitTestRepos.run(repo, "git", "commit", "-am", "candidate change");
        candidateSha = GitTestRepos.shaOf(repo, "HEAD");
        runService = new RemediationRunService(FIXED_CLOCK, tempDir.resolve("runs"));
    }

    private JenkinsConfig config() {
        return new JenkinsConfig("https://jenkins.example.invalid", "WebApplicationDependencyValidation",
                "bot", "TOKEN-DO-NOT-LEAK", java.time.Duration.ofSeconds(60), java.time.Duration.ofMillis(10));
    }

    private Path attemptDirectory(int number) {
        return runService.unitDirectoryFor(RUN_ID, UNIT_ID)
                .resolve("jenkins-validation").resolve("attempt-" + number);
    }

    @Test
    @DisplayName("a successful build is recorded with the correct candidate identity in both artifacts")
    void happyPath() {
        FakeJenkinsClient fake = new FakeJenkinsClient();
        JenkinsValidationService service = new JenkinsValidationService(fake, config(), git, runService);

        JenkinsValidationOutcome outcome = service.validate(RUN_ID, UNIT_ID, repo, baselineSha, candidateSha);

        assertTrue(outcome.succeeded());
        assertEquals(baselineSha, outcome.baselineSha());
        assertEquals(candidateSha, outcome.candidateSha());
        assertTrue(Files.exists(attemptDirectory(1).resolve(JenkinsValidationService.TRIGGER_FILE)));
        assertTrue(Files.exists(attemptDirectory(1).resolve(JenkinsValidationService.RESULT_FILE)));
        assertTrue(Files.exists(attemptDirectory(1).resolve(JenkinsValidationService.PATCH_FILE)));
        assertEquals(1, fake.triggerCount());
        assertEquals(baselineSha, fake.lastTriggeredCandidate().baselineSha());
    }

    @Test
    @DisplayName("FAILED, ABORTED and UNSTABLE all map through without throwing")
    void nonSuccessResultsMapThrough() {
        for (JenkinsValidationStatus status : new JenkinsValidationStatus[] {
                JenkinsValidationStatus.FAILED, JenkinsValidationStatus.ABORTED, JenkinsValidationStatus.UNSTABLE}) {
            FakeJenkinsClient fake = new FakeJenkinsClient();
            fake.respondWith(new JenkinsBuildResult(status, 1, "https://jenkins.example.invalid/1/", 500L,
                    "Jenkins reported result " + status));
            JenkinsValidationService service = new JenkinsValidationService(fake, config(), git, runService);

            JenkinsValidationOutcome outcome =
                    service.validate(RUN_ID, UNIT_ID + "-" + status, repo, baselineSha, candidateSha);

            assertFalse(outcome.succeeded());
            assertEquals(status, outcome.status());
        }
    }

    @Test
    @DisplayName("a build that could not be triggered becomes COULD_NOT_TRIGGER, never an exception")
    void triggerFailureBecomesCouldNotTrigger() {
        FakeJenkinsClient fake = new FakeJenkinsClient();
        fake.failOnCallNumber(1, new JenkinsValidationException("connection refused"));
        JenkinsValidationService service = new JenkinsValidationService(fake, config(), git, runService);

        JenkinsValidationOutcome outcome = service.validate(RUN_ID, UNIT_ID, repo, baselineSha, candidateSha);

        assertEquals(JenkinsValidationStatus.COULD_NOT_TRIGGER, outcome.status());
        assertTrue(outcome.resultSummary().contains("connection refused"), outcome.resultSummary());
    }

    @Test
    @DisplayName("a timed-out wait is recorded as TIMED_OUT, distinct from COULD_NOT_TRIGGER")
    void timedOutWaitIsRecordedDistinctly() {
        FakeJenkinsClient fake = new FakeJenkinsClient();
        fake.respondWith(new JenkinsBuildResult(JenkinsValidationStatus.TIMED_OUT, null, null, null,
                "No definitive result arrived within the configured Jenkins build timeout."));
        JenkinsValidationService service = new JenkinsValidationService(fake, config(), git, runService);

        JenkinsValidationOutcome outcome = service.validate(RUN_ID, UNIT_ID, repo, baselineSha, candidateSha);

        assertEquals(JenkinsValidationStatus.TIMED_OUT, outcome.status());
        assertFalse(outcome.succeeded());
    }

    @Test
    @DisplayName("the heartbeat is invoked at least once while waiting")
    void heartbeatIsInvoked() {
        FakeJenkinsClient fake = new FakeJenkinsClient();
        AtomicInteger heartbeats = new AtomicInteger();
        com.tungsten.depbot.progress.RemediationProgressListener progress =
                new com.tungsten.depbot.progress.RemediationProgressListener() {
                    @Override
                    public void stepStarting(com.tungsten.depbot.progress.RemediationStep step, String c, String d) {
                    }

                    @Override
                    public void stepFinished(com.tungsten.depbot.progress.RemediationStep step, String c, String o) {
                    }

                    @Override
                    public void stepHeartbeat(com.tungsten.depbot.progress.RemediationStep step, String c, String d) {
                        heartbeats.incrementAndGet();
                    }
                };
        JenkinsValidationService service = new JenkinsValidationService(fake, config(), git, runService, progress);

        service.validate(RUN_ID, UNIT_ID, repo, baselineSha, candidateSha);

        assertTrue(heartbeats.get() >= 1);
    }

    @Test
    @DisplayName("a pre-existing result.json for the same candidate identity is returned without touching the client")
    void preExistingResultWithSameIdentityIsReused() throws IOException {
        FakeJenkinsClient fake = new FakeJenkinsClient();
        JenkinsValidationService first = new JenkinsValidationService(fake, config(), git, runService);
        JenkinsValidationOutcome firstOutcome = first.validate(RUN_ID, UNIT_ID, repo, baselineSha, candidateSha);
        assertEquals(1, fake.triggerCount());

        FakeJenkinsClient second = new FakeJenkinsClient();
        JenkinsValidationService retry = new JenkinsValidationService(second, config(), git, runService);
        JenkinsValidationOutcome retryOutcome = retry.validate(RUN_ID, UNIT_ID, repo, baselineSha, candidateSha);

        assertEquals(firstOutcome, retryOutcome);
        assertEquals(0, second.triggerCount(), "an already-resolved result must never reach the client again");
        assertEquals(0, second.waitForCompletionCount());
    }

    @Test
    @DisplayName("a pre-existing trigger.json for the same identity resumes waiting rather than re-triggering")
    void preExistingTriggerWithSameIdentityResumesWaitingWithoutRetriggering() throws IOException {
        JenkinsCandidate requested = new JenkinsCandidate(
                baselineSha, candidateSha, git.diffBinary(repo, baselineSha, candidateSha),
                git.treeSha(repo, candidateSha));
        JenkinsBuildRef ref = JenkinsBuildRef.queueItem("https://jenkins.example.invalid/queue/item/42/");
        writeJson(attemptDirectory(1).resolve(JenkinsValidationService.TRIGGER_FILE),
                new TestTriggerRecord(requested, ref));

        FakeJenkinsClient fake = new FakeJenkinsClient();
        JenkinsValidationService service = new JenkinsValidationService(fake, config(), git, runService);

        JenkinsValidationOutcome outcome = service.validate(RUN_ID, UNIT_ID, repo, baselineSha, candidateSha);

        assertTrue(outcome.succeeded());
        assertEquals(0, fake.triggerCount(), "a resumed attempt must never trigger a second build");
        assertEquals(1, fake.waitForCompletionCount());
    }

    @Test
    @DisplayName("a persisted attempt for a different candidate is never reused -- a new attempt is triggered instead")
    void mismatchedIdentityStartsANewAttempt() throws IOException, InterruptedException {
        FakeJenkinsClient firstClient = new FakeJenkinsClient();
        JenkinsValidationService first = new JenkinsValidationService(firstClient, config(), git, runService);
        first.validate(RUN_ID, UNIT_ID, repo, baselineSha, candidateSha);
        assertTrue(Files.exists(attemptDirectory(1).resolve(JenkinsValidationService.RESULT_FILE)));

        // A different candidate under the exact same unitId -- simulating a retried run whose
        // Implementation produced a different commit this time.
        Files.writeString(repo.resolve("file.txt"), "hello, changed differently\n", StandardCharsets.UTF_8);
        GitTestRepos.run(repo, "git", "commit", "-am", "a different candidate change");
        String otherCandidateSha = GitTestRepos.shaOf(repo, "HEAD");

        FakeJenkinsClient secondClient = new FakeJenkinsClient();
        JenkinsValidationService second = new JenkinsValidationService(secondClient, config(), git, runService);
        JenkinsValidationOutcome outcome =
                second.validate(RUN_ID, UNIT_ID, repo, baselineSha, otherCandidateSha);

        assertEquals(1, secondClient.triggerCount(), "the mismatched attempt-1 must never be treated as proof");
        assertEquals(otherCandidateSha, outcome.candidateSha());
        assertTrue(Files.exists(attemptDirectory(2).resolve(JenkinsValidationService.RESULT_FILE)));
        // attempt-1 is untouched -- still the original candidate's own result.
        String attempt1Json = Files.readString(attemptDirectory(1).resolve(JenkinsValidationService.RESULT_FILE));
        assertTrue(attempt1Json.contains(candidateSha), attempt1Json);
    }

    private void writeJson(Path path, Object document) throws IOException {
        Files.createDirectories(path.getParent());
        Files.writeString(path, mapper.writeValueAsString(document), StandardCharsets.UTF_8);
    }

    private record TestTriggerRecord(JenkinsCandidate candidate, JenkinsBuildRef ref) {
    }
}
