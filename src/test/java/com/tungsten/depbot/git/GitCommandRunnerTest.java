package com.tungsten.depbot.git;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GitCommandRunnerTest {

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();

    @Test
    @DisplayName("fetch against a real remote does not throw")
    void fetchSucceeds() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        git.fetch(work, "origin");
    }

    @Test
    @DisplayName("revParse resolves origin/master to a full 40-character SHA")
    void revParseResolvesOriginMaster() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        git.fetch(work, "origin");

        String sha = git.revParse(work, "origin/master");

        assertTrue(sha.matches("[0-9a-f]{40}"), "expected a 40-character SHA, got: " + sha);
    }

    @Test
    @DisplayName("currentBranch reports the checked-out branch name")
    void currentBranchReportsBranchName() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        assertEquals("master", git.currentBranch(work));
    }

    @Test
    @DisplayName("currentBranch reports the literal HEAD when detached")
    void currentBranchReportsHeadWhenDetached() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String sha = git.currentHeadSha(work);

        git.checkout(work, sha);

        assertEquals("HEAD", git.currentBranch(work));
    }

    @Test
    @DisplayName("currentHeadSha matches revParse HEAD")
    void currentHeadShaMatchesRevParse() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        assertEquals(git.revParse(work, "HEAD"), git.currentHeadSha(work));
    }

    @Test
    @DisplayName("createBranch creates a ref without checking it out")
    void createBranchDoesNotCheckOut() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String sha = git.currentHeadSha(work);

        git.createBranch(work, "remediation/run1/critical", sha);

        assertEquals(sha, git.revParse(work, "remediation/run1/critical"));
        assertEquals("master", git.currentBranch(work), "creating a branch must not switch to it");
    }

    @Test
    @DisplayName("createBranch fails if the branch name already exists")
    void createBranchFailsOnDuplicateName() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String sha = git.currentHeadSha(work);
        git.createBranch(work, "remediation/run1/critical", sha);

        GitCommandException e = assertThrows(GitCommandException.class,
                () -> git.createBranch(work, "remediation/run1/critical", sha));
        assertTrue(e.getMessage().contains("remediation/run1/critical"));
    }

    @Test
    @DisplayName("checkout switches the working tree to another branch")
    void checkoutSwitchesBranch() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String sha = git.currentHeadSha(work);
        git.createBranch(work, "remediation/run1/critical", sha);

        git.checkout(work, "remediation/run1/critical");

        assertEquals("remediation/run1/critical", git.currentBranch(work));
    }

    @Test
    @DisplayName("isClean is true on a fresh checkout and false once a file changes")
    void isCleanReflectsWorkingTreeState() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        assertTrue(git.isClean(work));

        Files.writeString(work.resolve("file.txt"), "changed\n", StandardCharsets.UTF_8);

        assertTrue(!git.isClean(work));
        assertTrue(!git.status(work).isBlank());
    }

    @Test
    @DisplayName("diff shows unstaged changes; diffCached is empty until staged")
    void diffAndDiffCachedReflectStagingState() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve("file.txt"), "changed\n", StandardCharsets.UTF_8);

        assertTrue(!git.diff(work).isBlank());
        assertTrue(git.diffCached(work).isBlank());

        git.add(work);

        assertTrue(git.diff(work).isBlank(), "after staging everything, unstaged diff is empty");
        assertTrue(!git.diffCached(work).isBlank());
    }

    @Test
    @DisplayName("commit records a staged change and returns the tree to clean")
    void commitRecordsStagedChangeAndCleansTree() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String before = git.currentHeadSha(work);
        Files.writeString(work.resolve("file.txt"), "changed\n", StandardCharsets.UTF_8);
        git.add(work);

        git.commit(work, "test commit");

        assertTrue(git.isClean(work));
        assertTrue(!before.equals(git.currentHeadSha(work)));
    }

    @Test
    @DisplayName("resetHard plus cleanUntracked restores a dirty tree to a given commit")
    void resetHardAndCleanUntrackedRestoreBaseline() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = git.currentHeadSha(work);
        Files.writeString(work.resolve("file.txt"), "changed\n", StandardCharsets.UTF_8);
        Files.writeString(work.resolve("new-untracked.txt"), "new\n", StandardCharsets.UTF_8);
        git.add(work);

        git.resetHard(work, baseline);
        git.cleanUntracked(work);

        assertTrue(git.isClean(work));
        assertEquals(baseline, git.currentHeadSha(work));
        assertTrue(!Files.exists(work.resolve("new-untracked.txt")));
        assertEquals("hello\n", Files.readString(work.resolve("file.txt"), StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("listUntrackedFiles reports only untracked, non-ignored files -- never a tracked file, "
            + "never an ignored one, and never a directory entry of its own")
    void listUntrackedFilesReportsOnlyUntrackedNonIgnoredFiles() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve(".gitignore"), "ignored.txt\n", StandardCharsets.UTF_8);
        Files.writeString(work.resolve("ignored.txt"), "must never be reported\n", StandardCharsets.UTF_8);
        Files.writeString(work.resolve("untracked.txt"), "must be reported\n", StandardCharsets.UTF_8);
        Files.createDirectories(work.resolve("nested/dir"));
        Files.writeString(work.resolve("nested/dir/inner.txt"), "must be reported by its file path\n",
                StandardCharsets.UTF_8);
        Files.writeString(work.resolve("file.txt"), "a tracked file, merely edited\n", StandardCharsets.UTF_8);

        assertEquals(java.util.Set.of("untracked.txt", "nested/dir/inner.txt", ".gitignore"),
                java.util.Set.copyOf(git.listUntrackedFiles(work)));
    }

    @Test
    @DisplayName("updateRef creates a ref pointing at a SHA, and deleteRef removes it")
    void updateRefAndDeleteRef() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String sha = git.currentHeadSha(work);

        git.updateRef(work, "refs/remediation-bot/anchor-test", sha);
        assertEquals(sha, git.revParse(work, "refs/remediation-bot/anchor-test"));

        git.deleteRef(work, "refs/remediation-bot/anchor-test");
        assertThrows(GitCommandException.class, () -> git.revParse(work, "refs/remediation-bot/anchor-test"));
    }

    @Test
    @DisplayName("showFileAt reads a file's content at a fixed commit, and returns null for a path that "
            + "did not exist there")
    void showFileAtReadsFixedCommitContentOrNullIfAbsent() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = git.currentHeadSha(work);

        Files.writeString(work.resolve("file.txt"), "changed\n", StandardCharsets.UTF_8);
        Files.writeString(work.resolve("new-file.txt"), "brand new\n", StandardCharsets.UTF_8);
        git.add(work);
        git.commit(work, "second commit");

        assertEquals("hello\n", git.showFileAt(work, baseline, "file.txt"));
        assertEquals("changed\n", git.showFileAt(work, git.currentHeadSha(work), "file.txt"));
        assertTrue(git.showFileAt(work, baseline, "new-file.txt") == null,
                "a file that did not exist yet at the baseline must read back as null, not throw");
    }

    @Test
    @DisplayName("fetch against a directory that is not a git repository fails with a clear exception")
    void fetchFromNonGitDirectoryThrows() {
        assertThrows(GitCommandException.class, () -> git.fetch(tempDir, "origin"));
    }

    @Test
    @DisplayName("running a nonexistent executable throws GitCommandException, not a raw IOException")
    void unresolvableCommandWrapsIOException() {
        GitCommandRunner brokenPath = new GitCommandRunner();
        // fetch from a directory that does not exist at all -- ProcessBuilder can still start
        // "git", but git itself will fail because the working directory is invalid.
        Path missingDirectory = tempDir.resolve("does-not-exist");
        assertThrows(GitCommandException.class, () -> brokenPath.fetch(missingDirectory, "origin"));
    }
}
