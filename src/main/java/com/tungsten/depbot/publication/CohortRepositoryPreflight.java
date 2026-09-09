package com.tungsten.depbot.publication;

import com.tungsten.depbot.git.GitCommandException;
import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.remediation.CohortsIndex;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/**
 * Confirms, immediately before a cohort is ever pushed, that the local repository genuinely still
 * matches what {@code cohorts.json} claims -- never trusting a branch name alone. {@link
 * PublicationEligibility} answers "is this cohort allowed to be published" from bot-owned validation
 * facts; this class answers a different question, "does the physical git state on disk actually agree
 * with the commit sequence {@code cohorts.json} recorded" -- a cheap, local check that catches a stale or
 * hand-edited {@code cohorts.json}, a branch someone touched between {@code remediate} and {@code
 * publish}, or a run directory copied alongside the wrong checkout.
 */
public final class CohortRepositoryPreflight {

    private CohortRepositoryPreflight() {
    }

    public static PreflightResult verify(GitCommandRunner git, Path repoPath, CohortsIndex.Entry cohort) {
        Objects.requireNonNull(git, "git");
        Objects.requireNonNull(repoPath, "repoPath");
        Objects.requireNonNull(cohort, "cohort");

        if (!git.branchExistsLocally(repoPath, cohort.branchName())) {
            return PreflightResult.failed("local branch " + cohort.branchName() + " does not exist");
        }

        String expectedTip = cohort.commits().get(cohort.commits().size() - 1).commitSha();
        String actualTip;
        try {
            actualTip = git.revParseCommit(repoPath, cohort.branchName());
        } catch (GitCommandException e) {
            return PreflightResult.failed(
                    "could not resolve the tip of " + cohort.branchName() + ": " + e.getMessage());
        }
        if (!expectedTip.equals(actualTip)) {
            return PreflightResult.failed("branch " + cohort.branchName() + " tip is " + actualTip
                    + ", but cohorts.json's last recorded commit is " + expectedTip);
        }

        List<String> history = git.commitHistory(repoPath, cohort.branchName());
        int previousIndex = -1;
        for (int i = cohort.commits().size() - 1; i >= 0; i--) {
            CohortsIndex.Commit commit = cohort.commits().get(i);
            int index = history.indexOf(commit.commitSha());
            if (index < 0) {
                return PreflightResult.failed("commit " + commit.commitSha() + " (group " + commit.groupId()
                        + ") is not reachable from " + cohort.branchName());
            }
            if (index <= previousIndex) {
                return PreflightResult.failed("commit " + commit.commitSha() + " (group " + commit.groupId()
                        + ") is out of the order recorded in cohorts.json");
            }
            previousIndex = index;
        }

        return PreflightResult.ok(expectedTip);
    }
}
