package com.tungsten.depbot.git;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemediationChangeCommitterTest {

    private static final String BRANCH = "remediation/run1/high/g__a";

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();
    private final RemediationChangeCommitter committer =
            new RemediationChangeCommitter(git, new RemediationDiffPolicy());

    private Path repo;
    private String baseline;

    @BeforeEach
    void prepareBranch() throws Exception {
        repo = GitTestRepos.createOriginAndSingleBranchClone(tempDir);
        git.createBranch(repo, BRANCH, GitTestRepos.shaOf(repo, "master"));
        git.checkout(repo, BRANCH);
        baseline = git.currentHeadSha(repo);
    }

    private void edit(String relativePath, String content) throws IOException {
        Path file = repo.resolve(relativePath);
        Files.createDirectories(file.getParent() == null ? repo : file.getParent());
        Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("a completed remediation whose diff passes the policy is committed on the branch")
    void completedAndCleanIsCommitted() throws Exception {
        edit("pom.xml", "<project><version>1.85</version></project>\n");

        ChangeOutcome outcome = committer.finalizeChange(repo, BRANCH, baseline, true, "remediate: g:a -> 1.85");

        assertEquals(ChangeDisposition.COMMITTED_PENDING_VALIDATION, outcome.disposition());
        assertTrue(outcome.committed());
        assertNotNull(outcome.commitSha());
        assertFalse(baseline.equals(git.currentHeadSha(repo)), "the branch tip must have moved");
        assertTrue(git.isClean(repo));
        assertTrue(outcome.patch().contains("1.85"), outcome.patch());
    }

    @Test
    @DisplayName("changes across many kinds of file are committed together; nothing is POM-only")
    void changesAcrossManyKindsOfFileAreCommitted() throws Exception {
        edit("pom.xml", "<project><properties><bc>1.85</bc></properties></project>\n");
        edit("modules/core/pom.xml", "<project/>\n");
        edit("src/main/java/com/example/Crypto.java", "class Crypto {}\n");
        edit("src/test/java/com/example/CryptoTest.java", "class CryptoTest {}\n");
        edit("src/main/resources/application.properties", "cipher=new\n");
        edit("THIRD-PARTY.txt", "bcprov 1.85\n");

        ChangeOutcome outcome = committer.finalizeChange(repo, BRANCH, baseline, true, "remediate: g:a");

        assertEquals(ChangeDisposition.COMMITTED_PENDING_VALIDATION, outcome.disposition());
        assertTrue(outcome.patch().contains("Crypto.java"), outcome.patch());
        assertTrue(outcome.patch().contains("CryptoTest.java"),
                "a test changed because the library changed is legitimate remediation work");
        assertTrue(outcome.patch().contains("THIRD-PARTY.txt"), outcome.patch());
    }

    @Test
    @DisplayName("an implementation that stopped has its partial edits undone, and they are undone in full")
    void stoppedWorkIsRolledBack() throws Exception {
        edit("pom.xml", "<project><version>1.85</version></project>\n");
        edit("brand-new-file.txt", "half-finished\n");

        ChangeOutcome outcome = committer.finalizeChange(repo, BRANCH, baseline, false, "unused");

        assertEquals(ChangeDisposition.ROLLED_BACK, outcome.disposition());
        assertNull(outcome.commitSha());
        assertEquals(baseline, git.currentHeadSha(repo));
        assertTrue(git.isClean(repo));
        assertFalse(Files.exists(repo.resolve("brand-new-file.txt")),
                "an untracked leftover would be picked up by the next unit's diff");
        assertTrue(outcome.reason().contains("did not complete"), outcome.reason());
    }

    @Test
    @DisplayName("the rejected diff is preserved even though the working tree no longer holds it")
    void rejectedDiffIsPreserved() throws Exception {
        edit("pom.xml", "<project><version>1.85</version></project>\n");

        ChangeOutcome outcome = committer.finalizeChange(repo, BRANCH, baseline, false, "unused");

        assertTrue(outcome.patch().contains("1.85"),
                "the diff is the most useful thing to look at afterwards and is gone from disk by then");
    }

    @Test
    @DisplayName("a completed remediation that trips the diff policy is rolled back with the violation named")
    void policyViolationIsRolledBack() throws Exception {
        edit("pom.xml", "<project><maven.test.skip>true</maven.test.skip></project>\n");

        ChangeOutcome outcome = committer.finalizeChange(repo, BRANCH, baseline, true, "remediate: g:a");

        assertEquals(ChangeDisposition.ROLLED_BACK, outcome.disposition());
        assertEquals(baseline, git.currentHeadSha(repo));
        assertFalse(outcome.policyViolations().isEmpty());
        assertTrue(outcome.reason().contains("diff policy"), outcome.reason());
    }

    @Test
    @DisplayName("a secret-looking file is refused, however complete the remediation claims to be")
    void secretLookingFileIsRefused() throws Exception {
        edit(".env.local", "MEND_USER_KEY=real-looking-value\n");

        ChangeOutcome outcome = committer.finalizeChange(repo, BRANCH, baseline, true, "remediate: g:a");

        assertEquals(ChangeDisposition.ROLLED_BACK, outcome.disposition());
        assertFalse(Files.exists(repo.resolve(".env.local")));
    }

    @Test
    @DisplayName("changes staged by anything other than the orchestrator are refused")
    void preStagedChangesAreRefused() throws Exception {
        edit("pom.xml", "<project/>\n");
        GitTestRepos.run(repo, "git", "add", "pom.xml");

        ChangeOutcome outcome = committer.finalizeChange(repo, BRANCH, baseline, true, "remediate: g:a");

        assertEquals(ChangeDisposition.ROLLED_BACK, outcome.disposition());
        assertTrue(String.join(" ", outcome.policyViolations()).contains("git add"),
                outcome.policyViolations().toString());
    }

    @Test
    @DisplayName("an untouched tree is neither committed nor rolled back")
    void untouchedTreeIsNeither() {
        ChangeOutcome outcome = committer.finalizeChange(repo, BRANCH, baseline, true, "remediate: g:a");

        assertEquals(ChangeDisposition.NO_CHANGES, outcome.disposition());
        assertEquals("", outcome.patch());
        assertEquals(baseline, git.currentHeadSha(repo));
        assertTrue(outcome.reason().contains("changed nothing"), outcome.reason());
    }

    @Test
    @DisplayName("a stop that changed nothing says so, rather than claiming a rollback happened")
    void stopWithNoChangesIsReportedHonestly() {
        ChangeOutcome outcome = committer.finalizeChange(repo, BRANCH, baseline, false, "unused");

        assertEquals(ChangeDisposition.NO_CHANGES, outcome.disposition());
        assertTrue(outcome.reason().contains("without changing anything"), outcome.reason());
    }

    @Test
    @DisplayName("a rollback never disturbs an earlier commit already on the same branch")
    void rollbackLeavesEarlierCommitsAlone() throws Exception {
        edit("pom.xml", "<project><version>1.85</version></project>\n");
        ChangeOutcome first = committer.finalizeChange(repo, BRANCH, baseline, true, "first remediation");
        String afterFirst = git.currentHeadSha(repo);
        assertTrue(first.committed());

        edit("pom.xml", "<project><maven.test.skip>true</maven.test.skip></project>\n");
        committer.finalizeChange(repo, BRANCH, afterFirst, true, "second remediation");

        assertEquals(afterFirst, git.currentHeadSha(repo));
        assertTrue(Files.readString(repo.resolve("pom.xml")).contains("1.85"),
                "the first remediation's work must survive the second's rollback");
    }

    // ---- ending up on the wrong branch fails closed, rather than transplanting anything -------------

    @Test
    @DisplayName("uncommitted work left on a different branch is never carried over -- fails closed, needs a human")
    void uncommittedWorkOnADifferentBranchFailsClosed() throws Exception {
        // Stands in for Claude using its own local git to switch away mid-session.
        GitTestRepos.run(repo, "git", "checkout", "-q", "-b", "somewhere-else");
        edit("pom.xml", "<project><version>1.85</version></project>\n");

        ChangeOutcome outcome = committer.finalizeChange(repo, BRANCH, baseline, true, "remediate: g:a -> 1.85");

        assertEquals(ChangeDisposition.ROLLED_BACK, outcome.disposition());
        assertNull(outcome.commitSha());
        assertEquals("", outcome.patch(), "nothing from the wrong branch may be surfaced as the remediation diff");
        assertEquals(BRANCH, git.currentBranch(repo), "the checkout must land back on the remediation branch");
        assertEquals(baseline, git.currentHeadSha(repo));
        assertTrue(git.isClean(repo));
        assertTrue(outcome.reason().contains("somewhere-else"), outcome.reason());
        assertTrue(outcome.reason().contains("needs a human"), outcome.reason());
        assertFalse(Files.exists(repo.resolve("pom.xml")),
                "the pom.xml edited on the wrong branch must never appear on the remediation branch");
    }

    @Test
    @DisplayName("a commit made on a different branch is never carried over either -- fails closed, commit stays behind")
    void commitOnADifferentBranchFailsClosed() throws Exception {
        GitTestRepos.run(repo, "git", "checkout", "-q", "-b", "somewhere-else");
        edit("pom.xml", "<project><maven.test.skip>true</maven.test.skip></project>\n");
        GitTestRepos.run(repo, "git", "add", "-A");
        GitTestRepos.run(repo, "git", "commit", "-q", "-m", "self-commit-on-wrong-branch");
        String wrongBranchSha = git.currentHeadSha(repo);

        ChangeOutcome outcome = committer.finalizeChange(repo, BRANCH, baseline, true, "remediate: g:a");

        assertEquals(ChangeDisposition.ROLLED_BACK, outcome.disposition());
        assertNull(outcome.commitSha());
        assertEquals(BRANCH, git.currentBranch(repo));
        assertEquals(baseline, git.currentHeadSha(repo));
        assertTrue(git.isClean(repo));
        assertTrue(outcome.reason().contains("somewhere-else"), outcome.reason());

        // The stray commit is left exactly where Claude made it -- not deleted, not moved, not reviewed.
        assertEquals(wrongBranchSha, GitTestRepos.shaOf(repo, "somewhere-else"));
    }

    // ---- scoped rollback cleanup: never an indiscriminate whole-repo git clean -fd ------------------
    //
    // Production defect (pilot 20260908-220923-771c06): both Jackson attempts' rollback reported "git
    // clean -fd failed" with repeated "Permission denied" against .settings and other pre-existing,
    // unrelated untracked directories nothing in this class has any business touching. A rollback must
    // remove only the untracked paths this specific attempt itself created since its own baseline
    // snapshot -- never a pre-existing untracked path, whatever it is or however it got there.

    @Test
    @DisplayName("a pre-existing untracked file survives rollback untouched -- it is never a candidate "
            + "for removal in the first place, whatever this attempt itself created alongside it")
    void preExistingUntrackedFileSurvivesRollback() throws Exception {
        Path preExisting = repo.resolve("pre-existing.settings-style.txt");
        Files.writeString(preExisting, "already here before this attempt began\n", StandardCharsets.UTF_8);
        List<String> baselineUntrackedFiles = git.listUntrackedFiles(repo);

        // The diff-policy check ("skipTests" is a recognised violation marker) must refuse *before*
        // staging, not merely after: git add -A unconditionally stages -- and a subsequent
        // git reset --hard therefore unconditionally removes -- any untracked file that is not
        // gitignored, tracked or not. Only a before-staging refusal skips git add entirely, which is the
        // only way an untracked file can survive to be governed by this class's own scoped cleanup at
        // all, rather than being swept away earlier by the ordinary stage-everything step.
        edit("file.txt", "changed, tracked -- and carries a skipTests marker for this fixture\n");
        edit("brand-new-file.txt", "created by this attempt, must be removed\n");

        ChangeOutcome outcome = committer.finalizeChange(
                repo, BRANCH, baseline, false, null, "unused", baselineUntrackedFiles);

        assertEquals(ChangeDisposition.ROLLED_BACK, outcome.disposition());
        assertTrue(Files.exists(preExisting), "a pre-existing untracked path must never be removed by rollback");
        assertFalse(Files.exists(repo.resolve("brand-new-file.txt")),
                "an untracked file this attempt itself created must still be removed");
    }

    @Test
    @DisplayName("an untracked file created during the attempt, nested in a brand-new directory, is removed "
            + "together with the now-empty directory it leaves behind")
    void attemptCreatedNestedUntrackedFileAndItsNewDirectoryAreRemoved() throws Exception {
        edit("file.txt", "changed, but the implementation never claimed to finish\n");
        edit("brand-new-dir/nested/leftover.txt", "half-finished\n");

        ChangeOutcome outcome = committer.finalizeChange(repo, BRANCH, baseline, false, "unused");

        assertEquals(ChangeDisposition.ROLLED_BACK, outcome.disposition());
        assertFalse(Files.exists(repo.resolve("brand-new-dir/nested/leftover.txt")));
        assertFalse(Files.exists(repo.resolve("brand-new-dir")),
                "the directory this attempt's own file creation implied should be gone too, not left empty");
    }

    @Test
    @DisplayName("an attempt-created untracked path that cannot be deleted makes the rollback fail loudly, "
            + "never a quiet, possibly-contaminated ROLLED_BACK outcome")
    void attemptCreatedUntrackedPathThatCannotBeDeletedFailsRollbackLoudly() throws Exception {
        // Files.deleteIfExists refuses a non-empty directory outright (DirectoryNotEmptyException) --
        // a deterministic, platform-independent stand-in for "this attempt-created path could not
        // actually be removed" that does not depend on OS-specific file-locking behaviour. The directory's
        // own content is a TRACKED file (committed before this test's own baseline), so it is never itself
        // a candidate this class's real untracked-file removal would delete out from under the directory
        // first -- only the faked "undeletable-dir" entry below asks this class to remove the directory.
        Files.createDirectories(repo.resolve("undeletable-dir"));
        Files.writeString(repo.resolve("undeletable-dir/inner.txt"), "tracked content\n", StandardCharsets.UTF_8);
        GitTestRepos.run(repo, "git", "add", "-A");
        GitTestRepos.run(repo, "git", "commit", "-q", "-m", "pre-existing tracked file inside a directory");
        String localBaseline = git.currentHeadSha(repo);

        // Overrides both listUntrackedFiles and status consistently -- the final clean-relative-to-
        // baseline check cross-verifies against real "git status" independently of the untracked-file
        // listing used to decide what to delete, precisely so a fake that only lied to one of them could
        // never demonstrate this contract at all.
        GitCommandRunner reportingAnExtraUntrackedDirectory = new GitCommandRunner() {
            @Override
            public List<String> listUntrackedFiles(Path repoDirectory) {
                List<String> reported = new java.util.ArrayList<>(super.listUntrackedFiles(repoDirectory));
                reported.add("undeletable-dir");
                return reported;
            }

            @Override
            public String status(Path repoDirectory) {
                return super.status(repoDirectory) + "?? undeletable-dir/\n";
            }
        };
        RemediationChangeCommitter failingCommitter =
                new RemediationChangeCommitter(reportingAnExtraUntrackedDirectory, new RemediationDiffPolicy());
        // Refuses before staging (see preExistingUntrackedFileSurvivesRollback's own comment on why) --
        // otherwise git add -A would stage undeletable-dir/inner.txt itself, and the reset --hard that
        // follows would remove it before this class's own cleanup ever runs, defeating this fixture.
        // file.txt, not pom.xml, is the file this fixture repository already has tracked at baseline.
        edit("file.txt", "changed, tracked -- and carries a skipTests marker for this fixture\n");

        assertThrows(GitCommandException.class,
                () -> failingCommitter.finalizeChange(repo, BRANCH, localBaseline, false, "unused"));
        assertTrue(Files.exists(repo.resolve("undeletable-dir/inner.txt")),
                "the path that could not be removed must still be there -- nothing here is left half-done");
    }

    @Test
    @DisplayName("an ordinary rollback with nothing untracked left behind carries no diagnostic detail")
    void ordinaryRollbackHasNoDiagnosticDetail() throws Exception {
        edit("file.txt", "changed, but the implementation never claimed to finish\n");

        ChangeOutcome outcome = committer.finalizeChange(repo, BRANCH, baseline, false, "unused");

        assertEquals(ChangeDisposition.ROLLED_BACK, outcome.disposition());
        assertNull(outcome.diagnosticDetail());
    }

    @Test
    @DisplayName("a self-commit made on the correct remediation branch is still reconciled and reviewed normally")
    void selfCommitOnTheCorrectBranchIsStillReconciled() throws Exception {
        edit("pom.xml", "<project><version>1.85</version></project>\n");
        GitTestRepos.run(repo, "git", "add", "-A");
        GitTestRepos.run(repo, "git", "commit", "-q", "-m", "self-commit-on-the-right-branch");

        ChangeOutcome outcome = committer.finalizeChange(repo, BRANCH, baseline, true, "remediate: g:a -> 1.85");

        assertEquals(ChangeDisposition.COMMITTED_PENDING_VALIDATION, outcome.disposition());
        assertEquals(BRANCH, git.currentBranch(repo));
        assertTrue(outcome.patch().contains("1.85"), outcome.patch());
        assertTrue(git.isClean(repo));

        String history = GitTestRepos.readOutput(repo, "git", "log", "--format=%H %s", baseline + ".." + BRANCH);
        List<String> commitLines = history.lines().filter(line -> !line.isBlank()).toList();
        assertEquals(1, commitLines.size(), "expected exactly one commit beyond the base: " + history);
    }
}
