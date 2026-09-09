package com.tungsten.depbot.git;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SourceRefVerifierTest {

    private static final String PLAUSIBLE_BUT_FICTIONAL_SHA = "0123456789abcdef0123456789abcdef01234567";

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();
    private final SourceRefVerifier verifier = new SourceRefVerifier(git);

    private Path repoWithRefs() throws IOException, InterruptedException {
        Path repo = GitTestRepos.createOriginAndSingleBranchClone(tempDir, "release/9.2");
        new RemoteRefsRefresher(git).refresh(repo);
        return repo;
    }

    @Test
    @DisplayName("a real remote branch verifies, and the SHA comes from git")
    void realRemoteBranchVerifies() throws Exception {
        Path repo = repoWithRefs();
        String actual = GitTestRepos.shaOf(repo, "refs/remotes/origin/release/9.2");

        SourceRefVerification verification =
                verifier.verify(repo, "origin/release/9.2", PLAUSIBLE_BUT_FICTIONAL_SHA);

        assertTrue(verification.verified(), verification.failureReason());
        assertEquals("refs/remotes/origin/release/9.2", verification.resolvedRef());
        assertEquals(actual, verification.resolvedSha());
    }

    @Test
    @DisplayName("the SHA the assessment claimed is never what is resolved, and a mismatch is not fatal")
    void claimedShaIsIgnoredAndAMismatchIsRecordedNotFatal() throws Exception {
        Path repo = repoWithRefs();

        SourceRefVerification verification =
                verifier.verify(repo, "origin/release/9.2", PLAUSIBLE_BUT_FICTIONAL_SHA);

        assertTrue(verification.verified(),
                "git is authoritative; a wrong claim is information, not grounds to refuse");
        assertFalse(verification.claimMatched());
        assertEquals(PLAUSIBLE_BUT_FICTIONAL_SHA, verification.claimedSha());
        assertFalse(PLAUSIBLE_BUT_FICTIONAL_SHA.equals(verification.resolvedSha()),
                "the fictional SHA must not have been adopted");
    }

    @Test
    @DisplayName("a correct claim is recorded as matching")
    void correctClaimIsRecordedAsMatching() throws Exception {
        Path repo = repoWithRefs();
        String actual = GitTestRepos.shaOf(repo, "refs/remotes/origin/release/9.2");

        assertTrue(verifier.verify(repo, "origin/release/9.2", actual).claimMatched());
    }

    @Test
    @DisplayName("a full ref name verifies as well as its short form")
    void fullRefNameVerifies() throws Exception {
        Path repo = repoWithRefs();

        SourceRefVerification verification =
                verifier.verify(repo, "refs/remotes/origin/release/9.2", null);

        assertTrue(verification.verified(), verification.failureReason());
        assertEquals("refs/remotes/origin/release/9.2", verification.resolvedRef());
    }

    @Test
    @DisplayName("a local branch and a tag verify too, since either can be a legitimate source")
    void localBranchAndTagVerify() throws Exception {
        Path repo = repoWithRefs();
        GitTestRepos.run(repo, "git", "tag", "v9.2.0");

        assertTrue(verifier.verify(repo, "master", null).verified());
        assertTrue(verifier.verify(repo, "v9.2.0", null).verified());
    }

    @Test
    @DisplayName("a ref that does not exist is rejected, and nothing is branched")
    void nonExistentRefIsRejected() throws Exception {
        Path repo = repoWithRefs();

        SourceRefVerification verification =
                verifier.verify(repo, "origin/release/does-not-exist", PLAUSIBLE_BUT_FICTIONAL_SHA);

        assertFalse(verification.verified());
        assertNull(verification.resolvedSha());
        assertTrue(verification.failureReason().contains("No ref named"), verification.failureReason());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "master~5",
            "origin/master^2",
            "HEAD@{1}",
            "release/*",
            "origin/master:pom.xml",
            "refs/heads/../../etc",
            "origin/ master",
    })
    @DisplayName("revision syntax and globs are refused, even when git would happily resolve them")
    void revisionSyntaxIsRefused(String expression) throws Exception {
        Path repo = repoWithRefs();

        SourceRefVerification verification = verifier.verify(repo, expression, null);

        assertFalse(verification.verified(),
                "a remediation branch must never be cut from a computed revision: " + expression);
        assertNull(verification.resolvedSha());
    }

    @Test
    @DisplayName("master~1 resolves in git but is still refused here, which is the point")
    void aResolvableRevisionIsStillRefused() throws Exception {
        Path repo = repoWithRefs();
        GitTestRepos.run(repo, "git", "commit", "-q", "--allow-empty", "-m", "second");

        assertFalse(git.revParseCommit(repo, "master~1").isBlank(),
                "git resolves it, so refusing it has to be this class's own decision");
        assertFalse(verifier.verify(repo, "master~1", null).verified());
    }

    @Test
    @DisplayName("an option-looking ref is refused before it can reach git as a flag")
    void optionLookingRefIsRefused() throws Exception {
        Path repo = repoWithRefs();

        SourceRefVerification verification = verifier.verify(repo, "--all", null);

        assertFalse(verification.verified());
        assertTrue(verification.failureReason().contains("dash"), verification.failureReason());
    }

    @Test
    @DisplayName("an ambiguous short name is refused rather than guessed at")
    void ambiguousShortNameIsRefused() throws Exception {
        Path repo = repoWithRefs();
        // A local branch and a tag that both shorten to "ambiguous".
        GitTestRepos.run(repo, "git", "branch", "ambiguous", "master");
        GitTestRepos.run(repo, "git", "tag", "ambiguous", "master");

        SourceRefVerification verification = verifier.verify(repo, "ambiguous", null);

        assertFalse(verification.verified());
        assertTrue(verification.failureReason().contains("ambiguous"), verification.failureReason());
        assertTrue(verification.failureReason().contains("refs/heads/ambiguous"),
                verification.failureReason());
        assertTrue(verification.failureReason().contains("refs/tags/ambiguous"),
                verification.failureReason());
    }

    @Test
    @DisplayName("no ref at all is refused with a reason that says why nothing can be branched")
    void missingRefIsRefused() throws Exception {
        Path repo = repoWithRefs();

        assertFalse(verifier.verify(repo, null, null).verified());
        assertFalse(verifier.verify(repo, "   ", null).verified());
        assertTrue(verifier.verify(repo, null, null).failureReason().contains("named no source ref"));
    }

    @Test
    @DisplayName("an annotated tag is dereferenced to the commit it tags")
    void annotatedTagResolvesToItsCommit() throws Exception {
        Path repo = repoWithRefs();
        GitTestRepos.run(repo, "git", "tag", "-a", "v9.9.0", "-m", "annotated", "master");
        String masterSha = GitTestRepos.shaOf(repo, "master");

        SourceRefVerification verification = verifier.verify(repo, "v9.9.0", null);

        assertTrue(verification.verified(), verification.failureReason());
        assertEquals(masterSha, verification.resolvedSha(),
                "a branch cannot be created from a tag object, only from the commit under it");
    }
}
