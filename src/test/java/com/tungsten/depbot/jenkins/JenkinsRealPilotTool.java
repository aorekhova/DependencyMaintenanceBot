package com.tungsten.depbot.jenkins;

import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.git.GitWorktreeConfig;
import com.tungsten.depbot.git.RefsRefreshOutcome;
import com.tungsten.depbot.git.RemoteRefsRefresher;
import com.tungsten.depbot.git.SourceRefVerification;
import com.tungsten.depbot.git.SourceRefVerifier;
import com.tungsten.depbot.run.RemediationRunService;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A one-shot, manually-run pilot for the real {@link JenkinsApiClient}/{@link JenkinsValidationService}
 * against the real {@code WebApplicationDependencyValidation} Jenkins job -- test-scope tooling, never
 * shipped in the production jar, never invoked by {@code Main} or any automated test (it has no
 * {@code @Test} method, so Surefire never discovers or runs it).
 *
 * <p><strong>The baseline is always a verified GitLab ref, never the local checkout's own HEAD.</strong>
 * {@code WebApplicationDependencyValidation} checks out {@code BASE_COMMIT_SHA} from GitLab itself --
 * the local checkout's current {@code HEAD} could be a remediation branch or any other commit GitLab has
 * never seen, which would make Jenkins's own checkout step fail for a reason that has nothing to do with
 * what this pilot is meant to test. So this tool never reads local {@code HEAD} at all: it requires an
 * explicit {@code JENKINS_PILOT_BASE_REF} (an existing ref such as {@code origin/master} or
 * {@code origin/release/9.2}), fetches remote refs, and verifies that ref through git -- the exact same
 * {@link RemoteRefsRefresher}/{@link SourceRefVerifier} pair {@code VulnerabilityRemediationService}
 * itself uses -- before ever building a candidate from it.
 *
 * <p><strong>What this never does:</strong> the remote-refs fetch only updates {@code origin/*}
 * remote-tracking refs -- it never moves the checked-out branch, index or working files of
 * {@code WEBAPP_REPO_PATH} itself. The throwaway probe commit is made in a separate {@code git worktree}
 * (its own directory, sharing the same object database), cut from the verified GitLab SHA, and removed
 * again before this tool exits. Nothing is ever pushed -- the probe commit and its branch exist only in
 * the local object database and are deleted at the end. It never calls Mend, GitLab's write API, or
 * {@code VulnerabilityRemediationService} -- it drives {@link JenkinsValidationService} directly, the
 * exact same production class {@code remediate} would call, with nothing else in the pipeline involved.
 *
 * <p>Run it with (from the {@code DependencyMaintenanceBot} project root):
 * <pre>
 *   mvn -o package -DskipTests -q
 *   java -cp "target\dependency-maintenance-bot-1.0.0-SNAPSHOT.jar;target\test-classes" ^
 *        com.tungsten.depbot.jenkins.JenkinsRealPilotTool
 * </pre>
 *
 * <p>Required environment variables (values only, never printed by this tool):
 * {@code JENKINS_BASE_URL}, {@code JENKINS_USERNAME}, {@code JENKINS_API_TOKEN}, {@code WEBAPP_REPO_PATH},
 * and this tool's own {@code JENKINS_PILOT_BASE_REF} (an existing GitLab ref, e.g. {@code origin/master}
 * -- never guessed from the local checkout). Optional: {@code JENKINS_JOB_NAME} (defaults to
 * {@code WebApplicationDependencyValidation}), {@code JENKINS_BUILD_TIMEOUT_SECONDS},
 * {@code JENKINS_POLL_INTERVAL_SECONDS}.
 */
public final class JenkinsRealPilotTool {

    /** Test-tool-only -- never a production env var. An existing ref, never a local HEAD or a SHA. */
    public static final String JENKINS_PILOT_BASE_REF = "JENKINS_PILOT_BASE_REF";

    private JenkinsRealPilotTool() {
    }

    public static void main(String[] args) throws Exception {
        JenkinsConfig config = JenkinsConfig.fromEnvironment(System.getenv());
        GitWorktreeConfig webapp = GitWorktreeConfig.fromEnvironment();
        Path repoPath = webapp.repoPath();

        String requestedRef = System.getenv(JENKINS_PILOT_BASE_REF);
        if (requestedRef == null || requestedRef.isBlank()) {
            throw new IllegalStateException(JENKINS_PILOT_BASE_REF + " must be set to an existing GitLab "
                    + "ref (for example origin/master or origin/release/9.2) -- this tool never guesses a "
                    + "baseline from the local checkout's HEAD, since Jenkins checks out from GitLab, not "
                    + "from whatever this machine's working copy happens to be on.");
        }

        System.out.println("Job: " + config.jobName());
        System.out.println("Base URL: " + config.baseUrl());
        System.out.println("Repo: " + repoPath);

        GitCommandRunner git = new GitCommandRunner();

        System.out.println("Refreshing remote refs (fetch only -- never touches the checked-out branch) ...");
        RefsRefreshOutcome refsRefresh = new RemoteRefsRefresher(git).refresh(repoPath);
        if (!refsRefresh.refreshed()) {
            throw new IllegalStateException("Could not refresh remote refs: " + refsRefresh.message());
        }

        System.out.println("Verifying " + requestedRef + " against GitLab ...");
        SourceRefVerification verification = new SourceRefVerifier(git).verify(repoPath, requestedRef, null);
        if (!verification.verified()) {
            throw new IllegalStateException(
                    "Could not verify " + requestedRef + ": " + verification.failureReason());
        }
        String baselineSha = verification.resolvedSha();
        System.out.println("Verified GitLab baseline: " + verification.resolvedRef() + " @ " + baselineSha);

        String branchName = "jenkins-pilot-probe-" + System.currentTimeMillis();
        Path worktreeDir = Files.createTempDirectory("jenkins-pilot-worktree-");
        System.out.println("Throwaway worktree: " + worktreeDir + " (removed at the end)");

        try {
            run(repoPath, "worktree", "add", "-b", branchName, worktreeDir.toString(), baselineSha);

            Path probeFile = worktreeDir.resolve("JENKINS_PILOT_PROBE.md");
            Files.writeString(probeFile,
                    "Jenkins real-pilot probe file.\n"
                            + "Created only inside a throwaway git worktree/branch to exercise the real "
                            + "Jenkins validation transport end to end.\n"
                            + "Never pushed anywhere; the branch is deleted immediately after this pilot.\n",
                    StandardCharsets.UTF_8);
            run(worktreeDir, "add", "JENKINS_PILOT_PROBE.md");
            run(worktreeDir, "-c", "user.email=jenkins-pilot@local", "-c", "user.name=jenkins-pilot",
                    "commit", "-m", "jenkins pilot: throwaway probe commit, never pushed");

            String candidateSha = readOutput(worktreeDir, "rev-parse", "HEAD").strip();
            System.out.println("Candidate SHA (throwaway, local-only commit): " + candidateSha);

            RemediationRunService runService =
                    new RemediationRunService(Clock.systemUTC(), Path.of("reports", "runs"));
            JenkinsValidationService validationService =
                    new JenkinsValidationService(new JenkinsApiClient(config), config, git, runService);

            System.out.println("Triggering " + config.jobName() + " ... this can take a while.");
            JenkinsValidationOutcome outcome = validationService.validate(
                    "manual-pilot", "manual-pilot-unit", repoPath, baselineSha, candidateSha);

            System.out.println();
            System.out.println("=== Jenkins validation outcome ===");
            System.out.println("status: " + outcome.status());
            System.out.println("buildNumber: " + outcome.buildNumber());
            System.out.println("buildUrl: " + outcome.buildUrl());
            System.out.println("durationSeconds: " + outcome.durationSeconds());
            System.out.println("resultSummary: " + outcome.resultSummary());
            System.out.println();
            System.out.println("Artifacts written under reports/runs/manual-pilot/units/manual-pilot-unit/"
                    + "jenkins-validation/attempt-1/ (trigger/result JSON + the exact patch sent).");
        } finally {
            System.out.println("Cleaning up: removing the throwaway worktree and branch ...");
            runQuietly(repoPath, "worktree", "remove", "--force", worktreeDir.toString());
            runQuietly(repoPath, "branch", "-D", branchName);
            System.out.println("Done. " + repoPath + " is exactly as it was before this pilot ran.");
        }
    }

    private static void run(Path directory, String... args) throws IOException, InterruptedException {
        readOutput(directory, args);
    }

    private static void runQuietly(Path directory, String... args) {
        try {
            readOutput(directory, args);
        } catch (Exception e) {
            System.out.println("(cleanup warning, ignored: " + e.getMessage() + ")");
        }
    }

    private static String readOutput(Path directory, String... args) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add("git");
        command.addAll(Arrays.asList(args));
        Process process = new ProcessBuilder(command)
                .directory(directory.toFile())
                .redirectErrorStream(true)
                .start();
        String output;
        try (InputStream in = process.getInputStream()) {
            output = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IOException("git " + String.join(" ", args) + " failed (exit " + exitCode + "): " + output);
        }
        return output;
    }
}
