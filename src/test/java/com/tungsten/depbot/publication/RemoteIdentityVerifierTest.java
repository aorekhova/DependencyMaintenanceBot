package com.tungsten.depbot.publication;

import com.tungsten.depbot.git.GitCommandRunner;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemoteIdentityVerifierTest {

    private static final Path REPO = Path.of("repo");

    private static final class FixedRemoteUrlGit extends GitCommandRunner {
        private final String url;

        private FixedRemoteUrlGit(String url) {
            this.url = url;
        }

        @Override
        public String remoteUrl(Path repoDirectory, String remote) {
            return url;
        }
    }

    private static final class FixedProjectClient implements GitLabClient {
        private final ProjectMetadata project;

        private FixedProjectClient(ProjectMetadata project) {
            this.project = project;
        }

        @Override
        public ProjectMetadata fetchProject() {
            return project;
        }

        @Override
        public Optional<MergeRequestRef> findMergeRequestBySourceBranch(String sourceBranch) {
            throw new UnsupportedOperationException();
        }

        @Override
        public MergeRequestRef createMergeRequest(String s, String t, String title, String description) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void updateMergeRequestDescription(int mergeRequestIid, String description) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean commitCommentContains(String commitSha, String marker) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void postCommitComment(String commitSha, String body) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<IssueRef> findIssueContaining(String marker) {
            throw new UnsupportedOperationException();
        }

        @Override
        public IssueRef createIssue(String title, String description) {
            throw new UnsupportedOperationException();
        }
    }

    private static GitLabConfig config() {
        return new GitLabConfig("https://gitlab.example.com", "123", "token-not-logged", "origin");
    }

    @Test
    @DisplayName("host and path both matching verifies successfully")
    void hostAndPathBothMatch() {
        RemoteIdentityVerifier verifier = new RemoteIdentityVerifier();
        VerificationResult result = verifier.verify(
                new FixedRemoteUrlGit("git@gitlab.example.com:group/project.git"), REPO, "origin",
                new FixedProjectClient(new ProjectMetadata("123", "group/project", "url")), config());

        assertTrue(result.verified(), result.reason());
    }

    @Test
    @DisplayName("matching host but a different project path fails")
    void hostMatchesButPathDoesNot() {
        RemoteIdentityVerifier verifier = new RemoteIdentityVerifier();
        VerificationResult result = verifier.verify(
                new FixedRemoteUrlGit("git@gitlab.example.com:group/other-project.git"), REPO, "origin",
                new FixedProjectClient(new ProjectMetadata("123", "group/project", "url")), config());

        assertFalse(result.verified());
        assertTrue(result.reason().contains("group/other-project"), result.reason());
    }

    @Test
    @DisplayName("matching path but a different host fails")
    void pathMatchesButHostDoesNot() {
        RemoteIdentityVerifier verifier = new RemoteIdentityVerifier();
        VerificationResult result = verifier.verify(
                new FixedRemoteUrlGit("git@totally-different-host.com:group/project.git"), REPO, "origin",
                new FixedProjectClient(new ProjectMetadata("123", "group/project", "url")), config());

        assertFalse(result.verified());
        assertTrue(result.reason().contains("totally-different-host.com"), result.reason());
    }

    @Test
    @DisplayName("a numeric project id is still fully verifiable through the project's own path_with_namespace")
    void numericProjectIdIsFullyVerified() {
        RemoteIdentityVerifier verifier = new RemoteIdentityVerifier();
        VerificationResult result = verifier.verify(
                new FixedRemoteUrlGit("https://gitlab.example.com/group/webapp.git"), REPO, "origin",
                new FixedProjectClient(new ProjectMetadata("987654", "group/webapp", "url")), config());

        assertTrue(result.verified(), result.reason());
    }

    @Test
    @DisplayName("neither host nor path matching fails")
    void neitherHostNorPathMatch() {
        RemoteIdentityVerifier verifier = new RemoteIdentityVerifier();
        VerificationResult result = verifier.verify(
                new FixedRemoteUrlGit("git@other-host.com:other/project.git"), REPO, "origin",
                new FixedProjectClient(new ProjectMetadata("123", "group/project", "url")), config());

        assertFalse(result.verified());
    }
}
