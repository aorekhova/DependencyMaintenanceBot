package com.tungsten.depbot.jenkins;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.progress.RemediationProgressListener;
import com.tungsten.depbot.progress.RemediationStep;
import com.tungsten.depbot.report.SecretRedactor;
import com.tungsten.depbot.run.RemediationRunService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * The single entry point the orchestrator calls to run one Jenkins validation attempt -- either the
 * isolated attempt for one {@code RemediationGroup}'s own candidate, or the final integration attempt
 * for a cohort's fully-assembled shared branch. Both are the exact same operation from this class's own
 * point of view: a base SHA, a candidate SHA, and the diff/tree between them.
 *
 * <p><strong>Identity-aware idempotency.</strong> Before ever calling {@link JenkinsClient}, this checks
 * whether an {@code attempt-N} directory already on disk under this {@code unitId} was triggered for the
 * exact same {@link JenkinsCandidate} (baseline SHA, candidate SHA, expected tree SHA together) as the
 * one just requested. A path matching by coincidence is never treated as proof for a different candidate
 * -- a mismatch always starts a new, separate {@code attempt-N} directory rather than reusing or
 * overwriting the old one, so a retried run can never return a stale Jenkins result for new work, and
 * every attempt this application ever actually made against Jenkins remains on disk for good.
 *
 * <p>A build that could not even be queued ({@link JenkinsValidationException} from
 * {@link JenkinsClient#triggerBuild}) is caught here and turned into a {@code COULD_NOT_TRIGGER} outcome,
 * never thrown onward -- Jenkins being unreachable is an ordinary operational condition for this gate,
 * exactly like a failed remote-refs refresh elsewhere in this application, not a bug in this class.
 */
public final class JenkinsValidationService {

    static final String TRIGGER_FILE = "jenkins-trigger.json";
    static final String RESULT_FILE = "jenkins-result.json";
    static final String PATCH_FILE = "source-patch.diff";
    static final String CONSOLE_LOG_FILE = "console-log.txt";
    private static final String DIRECTORY_NAME = "jenkins-validation";
    private static final int CONSOLE_LOG_MAX_CHARS = 20_000;

    private final JenkinsClient jenkinsClient;
    private final JenkinsConfig config;
    private final GitCommandRunner git;
    private final RemediationRunService runService;
    private final RemediationProgressListener progress;
    private final SecretRedactor secretRedactor;
    private final ObjectWriter jsonWriter;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public JenkinsValidationService(
            JenkinsClient jenkinsClient, JenkinsConfig config, GitCommandRunner git,
            RemediationRunService runService) {
        this(jenkinsClient, config, git, runService, RemediationProgressListener.none(), SecretRedactor.none());
    }

    public JenkinsValidationService(
            JenkinsClient jenkinsClient, JenkinsConfig config, GitCommandRunner git,
            RemediationRunService runService, RemediationProgressListener progress) {
        this(jenkinsClient, config, git, runService, progress, SecretRedactor.none());
    }

    public JenkinsValidationService(
            JenkinsClient jenkinsClient, JenkinsConfig config, GitCommandRunner git,
            RemediationRunService runService, RemediationProgressListener progress, SecretRedactor secretRedactor) {
        this.jenkinsClient = Objects.requireNonNull(jenkinsClient, "jenkinsClient");
        this.config = Objects.requireNonNull(config, "config");
        this.git = Objects.requireNonNull(git, "git");
        this.runService = Objects.requireNonNull(runService, "runService");
        this.progress = Objects.requireNonNull(progress, "progress");
        this.secretRedactor = Objects.requireNonNull(secretRedactor, "secretRedactor");
        DefaultIndenter lfIndenter = new DefaultIndenter("  ", "\n");
        DefaultPrettyPrinter printer = new DefaultPrettyPrinter();
        printer.indentObjectsWith(lfIndenter);
        printer.indentArraysWith(lfIndenter);
        this.jsonWriter = mapper.writer(printer);
    }

    public JenkinsValidationOutcome validate(
            String runId, String unitId, Path repoPath, String baselineSha, String candidateSha) {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(unitId, "unitId");
        Objects.requireNonNull(repoPath, "repoPath");
        Objects.requireNonNull(baselineSha, "baselineSha");
        Objects.requireNonNull(candidateSha, "candidateSha");

        String patch = git.diffBinary(repoPath, baselineSha, candidateSha);
        String treeSha = git.treeSha(repoPath, candidateSha);
        JenkinsCandidate requested = new JenkinsCandidate(baselineSha, candidateSha, patch, treeSha);

        Path baseDirectory = runService.unitDirectoryFor(runId, unitId).resolve(DIRECTORY_NAME);
        int attempt = 1;
        while (true) {
            Path attemptDirectory = baseDirectory.resolve("attempt-" + attempt);
            Path resultFile = attemptDirectory.resolve(RESULT_FILE);
            Path triggerFile = attemptDirectory.resolve(TRIGGER_FILE);

            if (Files.exists(resultFile)) {
                ResultRecord persisted = readJson(resultFile, ResultRecord.class);
                if (persisted.candidate().sameIdentity(requested)) {
                    return persisted.outcome();
                }
                attempt++;
                continue;
            }
            if (Files.exists(triggerFile)) {
                TriggerRecord persisted = readJson(triggerFile, TriggerRecord.class);
                if (persisted.candidate().sameIdentity(requested)) {
                    return waitAndRecord(unitId, attemptDirectory, requested, persisted.ref());
                }
                attempt++;
                continue;
            }
            return triggerAndWait(unitId, attemptDirectory, requested);
        }
    }

    private JenkinsValidationOutcome triggerAndWait(String unitId, Path attemptDirectory, JenkinsCandidate requested) {
        runService.writeAttemptFile(attemptDirectory.resolve(PATCH_FILE), requested.sourcePatch());

        JenkinsBuildRef ref;
        try {
            ref = jenkinsClient.triggerBuild(requested);
        } catch (JenkinsValidationException e) {
            JenkinsValidationOutcome outcome = new JenkinsValidationOutcome(
                    JenkinsValidationStatus.COULD_NOT_TRIGGER, config.jobName(), null, null,
                    requested.baselineSha(), requested.candidateSha(), requested.expectedTreeSha(), null,
                    "Could not trigger " + config.jobName() + ": " + e.getMessage());
            writeJson(attemptDirectory.resolve(RESULT_FILE), new ResultRecord(requested, outcome));
            return outcome;
        }

        writeJson(attemptDirectory.resolve(TRIGGER_FILE), new TriggerRecord(requested, ref));
        return waitAndRecord(unitId, attemptDirectory, requested, ref);
    }

    private JenkinsValidationOutcome waitAndRecord(
            String unitId, Path attemptDirectory, JenkinsCandidate requested, JenkinsBuildRef ref) {
        progress.stepStarting(RemediationStep.JENKINS_VALIDATION, unitId, config.jobName());
        Runnable heartbeat = () -> progress.stepHeartbeat(RemediationStep.JENKINS_VALIDATION, unitId, null);

        JenkinsBuildResult result =
                jenkinsClient.waitForCompletion(ref, config.buildTimeout(), config.pollInterval(), heartbeat);

        progress.stepFinished(RemediationStep.JENKINS_VALIDATION, unitId, result.status().name());

        Long durationSeconds = result.durationMillis() == null ? null : result.durationMillis() / 1000;
        String consoleLogExcerpt = null;
        if (!result.status().succeeded() && result.buildNumber() != null) {
            String rawLog = jenkinsClient.fetchConsoleLog(result.buildNumber());
            String truncated = JenkinsConsoleLogExcerpt.truncate(rawLog, CONSOLE_LOG_MAX_CHARS);
            consoleLogExcerpt = secretRedactor.redact(truncated);
            if (consoleLogExcerpt != null && !consoleLogExcerpt.isBlank()) {
                runService.writeAttemptFile(attemptDirectory.resolve(CONSOLE_LOG_FILE), consoleLogExcerpt);
            }
        }
        JenkinsValidationOutcome outcome = new JenkinsValidationOutcome(
                result.status(), config.jobName(), result.buildNumber(), result.buildUrl(),
                requested.baselineSha(), requested.candidateSha(), requested.expectedTreeSha(),
                durationSeconds, result.resultSummary(), consoleLogExcerpt);
        writeJson(attemptDirectory.resolve(RESULT_FILE), new ResultRecord(requested, outcome));
        return outcome;
    }

    private void writeJson(Path path, Object document) {
        try {
            runService.writeAttemptFile(path, jsonWriter.writeValueAsString(document) + "\n");
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not render " + path + " as JSON", e);
        }
    }

    private <T> T readJson(Path path, Class<T> type) {
        try {
            return mapper.readValue(Files.readString(path, StandardCharsets.UTF_8), type);
        } catch (IOException e) {
            throw new IllegalStateException("Could not read " + path, e);
        }
    }

    private record TriggerRecord(JenkinsCandidate candidate, JenkinsBuildRef ref) {
    }

    private record ResultRecord(JenkinsCandidate candidate, JenkinsValidationOutcome outcome) {
    }
}
