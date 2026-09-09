package com.tungsten.depbot.publication;

import com.tungsten.depbot.git.GitCommandException;
import com.tungsten.depbot.git.GitCommandRunner;

import java.net.URI;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Confirms, once per {@code publish} run and before any mutating GitLab call, that the checkout's git
 * remote genuinely points at the same GitLab project {@link GitLabConfig} names -- both the host and the
 * project path, never host alone. A numeric {@code GITLAB_PROJECT_ID} is fully verifiable too: {@link
 * GitLabClient#fetchProject()} is a real, read-only {@code GET} that resolves it to GitLab's own {@code
 * path_with_namespace}, which is compared against the path parsed from {@code git remote get-url}.
 *
 * <p>This is a production preflight, not a manual-pilot-only step: {@code GitLabPublicationService}
 * calls it unconditionally at the start of every {@code publish}/{@code preview} call, before the first
 * cohort is even looked at. A mismatch stops the entire run -- remote identity is a fact about the whole
 * checkout, not about one cohort.
 */
public class RemoteIdentityVerifier {

    public VerificationResult verify(
            GitCommandRunner git, Path repoPath, String remoteName, GitLabClient client, GitLabConfig config) {
        Objects.requireNonNull(git, "git");
        Objects.requireNonNull(repoPath, "repoPath");
        Objects.requireNonNull(remoteName, "remoteName");
        Objects.requireNonNull(client, "client");
        Objects.requireNonNull(config, "config");

        String remoteUrl;
        try {
            remoteUrl = git.remoteUrl(repoPath, remoteName);
        } catch (GitCommandException e) {
            return VerificationResult.mismatch(
                    "could not read the URL of git remote \"" + remoteName + "\": " + e.getMessage());
        }

        ParsedRemote parsed;
        try {
            parsed = GitRemoteUrlParser.parse(remoteUrl);
        } catch (GitLabPublicationException e) {
            return VerificationResult.mismatch(
                    "could not parse the URL of git remote \"" + remoteName + "\": " + e.getMessage());
        }

        ProjectMetadata project;
        try {
            project = client.fetchProject();
        } catch (RuntimeException e) {
            return VerificationResult.mismatch("could not fetch project metadata from GitLab: " + e.getMessage());
        }

        URI baseUri = URI.create(config.baseUrl());
        boolean hostMatches = parsed.host().equalsIgnoreCase(baseUri.getHost());
        boolean pathMatches = parsed.path().equalsIgnoreCase(project.pathWithNamespace());

        if (!hostMatches || !pathMatches) {
            return VerificationResult.mismatch("git remote \"" + remoteName + "\" (host=" + parsed.host()
                    + ", path=" + parsed.path() + ") does not match the configured GitLab project (host="
                    + baseUri.getHost() + ", path=" + project.pathWithNamespace()
                    + ") -- refusing to push or mutate anything");
        }
        return VerificationResult.success();
    }
}
