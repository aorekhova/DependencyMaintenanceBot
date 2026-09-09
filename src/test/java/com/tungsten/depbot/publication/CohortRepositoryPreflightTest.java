package com.tungsten.depbot.publication;

import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.git.GitTestRepos;
import com.tungsten.depbot.remediation.CohortsIndex;
import com.tungsten.depbot.remediation.RemediationCohort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CohortRepositoryPreflightTest {

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();
    private Path repo;

    @BeforeEach
    void setUp() throws Exception {
        repo = GitTestRepos.createOriginAndClone(tempDir);
    }

    private String commit(String branchName, String fileName, String content) throws Exception {
        Files.writeString(repo.resolve(fileName), content, StandardCharsets.UTF_8);
        GitTestRepos.run(repo, "git", "add", "-A");
        GitTestRepos.run(repo, "git", "commit", "-q", "-m", fileName);
        return git.currentHeadSha(repo);
    }

    @Test
    @DisplayName("a branch matching the recorded single commit passes")
    void singleCommitMatches() throws Exception {
        String branchName = "remediation/run1/branch";
        git.createBranch(repo, branchName, git.currentHeadSha(repo));
        git.checkout(repo, branchName);
        String sha = commit(branchName, "a.txt", "a\n");

        CohortsIndex.Entry cohort = new CohortsIndex.Entry(branchName, "refs/remotes/origin/master", "basesha",
                RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-a", sha, "path")));

        PreflightResult result = CohortRepositoryPreflight.verify(git, repo, cohort);

        assertTrue(result.ok(), result.reason());
        assertTrue(result.expectedTip().equals(sha));
    }

    @Test
    @DisplayName("a multi-commit cohort in the recorded order passes")
    void multiCommitInOrderMatches() throws Exception {
        String branchName = "remediation/run1/branch";
        git.createBranch(repo, branchName, git.currentHeadSha(repo));
        git.checkout(repo, branchName);
        String shaA = commit(branchName, "a.txt", "a\n");
        String shaB = commit(branchName, "b.txt", "b\n");

        CohortsIndex.Entry cohort = new CohortsIndex.Entry(branchName, "refs/remotes/origin/master", "basesha",
                RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-a", shaA, "pathA"),
                        new CohortsIndex.Commit("g-b", shaB, "pathB")));

        PreflightResult result = CohortRepositoryPreflight.verify(git, repo, cohort);

        assertTrue(result.ok(), result.reason());
        assertTrue(result.expectedTip().equals(shaB));
    }

    @Test
    @DisplayName("a missing local branch fails")
    void missingBranchFails() {
        CohortsIndex.Entry cohort = new CohortsIndex.Entry("remediation/run1/nonexistent",
                "refs/remotes/origin/master", "basesha", RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-a", "0".repeat(40), "path")));

        PreflightResult result = CohortRepositoryPreflight.verify(git, repo, cohort);

        assertFalse(result.ok());
        assertTrue(result.reason().contains("does not exist"), result.reason());
    }

    @Test
    @DisplayName("a branch whose tip does not match the recorded last commit fails")
    void tipMismatchFails() throws Exception {
        String branchName = "remediation/run1/branch";
        git.createBranch(repo, branchName, git.currentHeadSha(repo));
        git.checkout(repo, branchName);
        commit(branchName, "a.txt", "a\n");
        String fabricatedSha = "1".repeat(40);

        CohortsIndex.Entry cohort = new CohortsIndex.Entry(branchName, "refs/remotes/origin/master", "basesha",
                RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-a", fabricatedSha, "path")));

        PreflightResult result = CohortRepositoryPreflight.verify(git, repo, cohort);

        assertFalse(result.ok());
        assertTrue(result.reason().contains("tip is"), result.reason());
    }

    @Test
    @DisplayName("commits recorded out of order fail, even when the recorded last entry still matches the "
            + "real tip -- both A and B are genuinely on the branch, just recorded in the wrong sequence")
    void outOfOrderCommitsFail() throws Exception {
        String branchName = "remediation/run1/branch";
        git.createBranch(repo, branchName, git.currentHeadSha(repo));
        git.checkout(repo, branchName);
        String shaA = commit(branchName, "a.txt", "a\n");
        String shaB = commit(branchName, "b.txt", "b\n");
        String shaC = commit(branchName, "c.txt", "c\n");

        // Real chronological order is A, B, C (C is the tip). Recorded here as B, A, C -- the last entry
        // (C) still matches the real tip, so only the earlier B/A swap can catch this.
        CohortsIndex.Entry cohort = new CohortsIndex.Entry(branchName, "refs/remotes/origin/master", "basesha",
                RemediationCohort.PublicationStatus.READY_TO_PUBLISH,
                List.of(new CohortsIndex.Commit("g-b", shaB, "pathB"),
                        new CohortsIndex.Commit("g-a", shaA, "pathA"),
                        new CohortsIndex.Commit("g-c", shaC, "pathC")));

        PreflightResult result = CohortRepositoryPreflight.verify(git, repo, cohort);

        assertFalse(result.ok());
        assertTrue(result.reason().contains("out of the order"), result.reason());
    }
}
