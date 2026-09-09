package com.tungsten.depbot.cli;

import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.git.GitTestRepos;
import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;
import com.tungsten.depbot.jenkins.JenkinsValidationStatus;
import com.tungsten.depbot.publication.FakeGitLabClient;
import com.tungsten.depbot.publication.GitLabClient;
import com.tungsten.depbot.publication.GitLabConfig;
import com.tungsten.depbot.publication.GitLabPublicationService;
import com.tungsten.depbot.publication.ProjectMetadata;
import com.tungsten.depbot.publication.RemoteIdentityVerifier;
import com.tungsten.depbot.publication.VerificationResult;
import com.tungsten.depbot.remediation.CohortsIndex;
import com.tungsten.depbot.remediation.CohortsIndexJsonReader;
import com.tungsten.depbot.remediation.CohortsIndexJsonRenderer;
import com.tungsten.depbot.remediation.RemediationCohort;
import com.tungsten.depbot.remediation.RemediationReport;
import com.tungsten.depbot.remediation.RemediationReportJsonRenderer;
import com.tungsten.depbot.remediation.RemediationSummary;
import com.tungsten.depbot.remediation.RemediationSummaryBuilder;
import com.tungsten.depbot.remediation.RemediationSummaryJsonReader;
import com.tungsten.depbot.remediation.RemediationSummaryJsonRenderer;
import com.tungsten.depbot.report.ConsoleReporter;
import com.tungsten.depbot.run.RemediationRunService;
import com.tungsten.depbot.validation.ValidationStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link PublishCommand} against a real git repository, a real {@code cohorts.json}/{@code
 * remediation-summary.json} pair written to disk exactly as {@code remediate} would leave them, and an
 * in-memory GitLab -- proving the standalone publication path reads a finished run back correctly,
 * {@code --dry-run} never mutates anything, and a real publish exits with the right code either way.
 */
class PublishCommandTest {

    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-08-21T00:00:00Z"), ZoneOffset.UTC);
    private static final String RUN_ID = "run1";
    private static final String VERIFIED_REF = "refs/remotes/origin/hotfix-2026.1";
    private static final String VERIFIED_SHA = "3473b0daa6be8017e6235f2e7ddba88f967f1309";

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();
    private Path repo;
    private RemediationRunService runService;
    private FakeGitLabClient gitLabClient;
    private ByteArrayOutputStream outBuffer;
    private ByteArrayOutputStream errBuffer;
    private ConsoleReporter reporter;

    @BeforeEach
    void setUp() throws Exception {
        repo = GitTestRepos.createOriginAndClone(tempDir);
        runService = new RemediationRunService(FIXED_CLOCK, tempDir.resolve("reports").resolve("runs"));
        gitLabClient = new FakeGitLabClient();
        outBuffer = new ByteArrayOutputStream();
        errBuffer = new ByteArrayOutputStream();
        reporter = new ConsoleReporter(
                new PrintStream(outBuffer, true, StandardCharsets.UTF_8),
                new PrintStream(errBuffer, true, StandardCharsets.UTF_8));
    }

    private String out() {
        return outBuffer.toString(StandardCharsets.UTF_8);
    }

    private String err() {
        return errBuffer.toString(StandardCharsets.UTF_8);
    }

    /** Never touches git or GitLab -- appropriate for a test that needs real push mechanics to work
     * against this fixture's own local bare-repo remote, which is not a real GitLab host. */
    private static final class AlwaysVerifiedIdentityVerifier extends RemoteIdentityVerifier {
        @Override
        public VerificationResult verify(
                GitCommandRunner git, Path repoPath, String remoteName, GitLabClient client, GitLabConfig config) {
            return VerificationResult.success();
        }
    }

    private PublishCommand command() {
        GitLabConfig config = new GitLabConfig("https://gitlab.example.invalid", "123", "token-not-logged", "origin");
        GitLabPublicationService publicationService = new GitLabPublicationService(
                repo, git, config, gitLabClient, runService, new AlwaysVerifiedIdentityVerifier());
        return new PublishCommand(publicationService, runService,
                new CohortsIndexJsonReader(), new RemediationSummaryJsonReader(), reporter);
    }

    /**
     * Uses the real {@link RemoteIdentityVerifier}, not a stub -- only safe for a test that never
     * actually needs {@code git push}/{@code git ls-remote} to succeed against a real host, since this
     * repoints the fixture's own remote at a non-functional host purely so its parsed identity matches
     * {@link GitLabConfig}.
     */
    private PublishCommand commandWithRealIdentityVerification() throws Exception {
        GitTestRepos.run(repo, "git", "remote", "set-url", "origin", "git@gitlab.example.invalid:group/webapp.git");
        gitLabClient.setProject(new ProjectMetadata("123", "group/webapp", "https://gitlab.example.invalid/group/webapp"));
        GitLabConfig config = new GitLabConfig("https://gitlab.example.invalid", "123", "token-not-logged", "origin");
        GitLabPublicationService publicationService =
                new GitLabPublicationService(repo, git, config, gitLabClient, runService);
        return new PublishCommand(publicationService, runService,
                new CohortsIndexJsonReader(), new RemediationSummaryJsonReader(), reporter);
    }

    private String commitOnNewBranch(String branchName, String fileName, String content) throws Exception {
        git.createBranch(repo, branchName, git.currentHeadSha(repo));
        git.checkout(repo, branchName);
        Files.writeString(repo.resolve(fileName), content, StandardCharsets.UTF_8);
        GitTestRepos.run(repo, "git", "add", "-A");
        GitTestRepos.run(repo, "git", "commit", "-q", "-m", "remediate: " + fileName);
        String sha = git.currentHeadSha(repo);
        git.checkout(repo, "master");
        return sha;
    }

    private static JenkinsValidationOutcome jenkinsSuccess(String candidateSha) {
        return new JenkinsValidationOutcome(JenkinsValidationStatus.SUCCESS, "WebApplicationDependencyValidation",
                1, "http://jenkins.example/job/x/1/", VERIFIED_SHA, candidateSha, "tree", 30L,
                "Jenkins reported result SUCCESS");
    }

    /** Writes cohorts.json/remediation-summary.json/remediation-report.json exactly as remediate would. */
    private void writeFinishedRun(String branchName, String commitSha) throws Exception {
        Path reportDirectory = runService.unitDirectoryFor(RUN_ID, "high__group__g-bcprov")
                .resolve("implementation").resolve("attempt-1");
        Files.createDirectories(reportDirectory);
        Path reportPath = reportDirectory.resolve("remediation-report.json");
        RemediationReport report = new RemediationReport("1.0", commitSha, "g-bcprov",
                List.of("org.bouncycastle:bcprov-jdk18on"), "changed", "necessary", "why", List.of("pom.xml"),
                "validated", List.of(), ValidationStatus.PASSED, ValidationStatus.PASSED,
                jenkinsSuccess(commitSha), jenkinsSuccess(commitSha));
        Files.writeString(reportPath, new RemediationReportJsonRenderer().render(report), StandardCharsets.UTF_8);

        CohortsIndex cohortsIndex = new CohortsIndex(RUN_ID, List.of(new CohortsIndex.Entry(
                branchName, VERIFIED_REF, VERIFIED_SHA, RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-bcprov", commitSha, reportPath.toString())))));
        Files.writeString(runService.runDirectoryFor(RUN_ID).resolve(CohortsIndexJsonReader.FILE_NAME),
                new CohortsIndexJsonRenderer().render(cohortsIndex), StandardCharsets.UTF_8);

        RemediationSummary summary = RemediationSummaryBuilder.build(
                RUN_ID, "2026-08-21T00:00:00Z", "opus", repo.toString(), null, List.of());
        Files.writeString(runService.runDirectoryFor(RUN_ID).resolve(RemediateCommand.SUMMARY_FILE),
                new RemediationSummaryJsonRenderer().render(summary), StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("a run with no persisted cohorts.json/remediation-summary.json is a publication source error")
    void missingRunIsAPublicationSourceError() {
        ExitCode code = command().run("no-such-run", false);

        assertEquals(ExitCode.PUBLICATION_SOURCE_ERROR, code);
        assertTrue(err().contains("Publication source error"), err());
    }

    @Test
    @DisplayName("--dry-run reads and reports the real preview without mutating anything, using the real "
            + "RemoteIdentityVerifier -- not a stub -- since preview never needs an actual git push to work")
    void dryRunReportsPreviewWithoutMutating() throws Exception {
        String branchName = "remediation/run1/hotfix-2026.1-3473b0daa6be";
        String commitSha = commitOnNewBranch(branchName, "pom.xml", "<project/>\n");
        writeFinishedRun(branchName, commitSha);

        ExitCode code = commandWithRealIdentityVerification().run(RUN_ID, true);

        assertEquals(ExitCode.SUCCESS, code);
        assertTrue(out().contains("DRY RUN"), out());
        assertTrue(out().contains("g-bcprov"), out());
        assertEquals(0, gitLabClient.mergeRequestCount());
        assertFalse(Files.exists(runService.runDirectoryFor(RUN_ID).resolve(GitLabPublicationService.PUBLICATION_FILE)));
    }

    @Test
    @DisplayName("a real publish exits SUCCESS and actually pushes and opens a Merge Request")
    void realPublishExitsSuccessAndActuallyPublishes() throws Exception {
        String branchName = "remediation/run1/hotfix-2026.1-3473b0daa6be";
        String commitSha = commitOnNewBranch(branchName, "pom.xml", "<project/>\n");
        writeFinishedRun(branchName, commitSha);

        ExitCode code = command().run(RUN_ID, false);

        assertEquals(ExitCode.SUCCESS, code);
        assertEquals(1, gitLabClient.mergeRequestCount());
        assertEquals(commitSha,
                GitTestRepos.shaOf(tempDir.resolve("origin.git"), "refs/heads/" + branchName));
        assertTrue(Files.exists(runService.runDirectoryFor(RUN_ID).resolve(GitLabPublicationService.PUBLICATION_FILE)));
    }

    @Test
    @DisplayName("a real publish that fails a cohort exits PUBLICATION_FAILED")
    void realPublishFailureExitsPublicationFailed() throws Exception {
        String branchName = "remediation/run1/hotfix-2026.1-3473b0daa6be";
        String commitSha = commitOnNewBranch(branchName, "pom.xml", "<project/>\n");
        writeFinishedRun(branchName, commitSha);
        gitLabClient.failOnCallNumber(2, new com.tungsten.depbot.publication.GitLabPublicationException("simulated"));

        ExitCode code = command().run(RUN_ID, false);

        assertEquals(ExitCode.PUBLICATION_FAILED, code);
    }
}
