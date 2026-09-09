package com.tungsten.depbot.publication;

import java.net.URI;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reduces a git remote URL -- SCP-like SSH ({@code git@host:group/project.git}), {@code ssh://}, or
 * {@code https://} -- to the host and project path {@link RemoteIdentityVerifier} compares against
 * GitLab's own project metadata. Never includes the raw URL in an exception message: an HTTPS remote can
 * legitimately embed a credential ({@code https://oauth2:TOKEN@host/...}), and this class has no way to
 * tell a credential-bearing URL from an ordinary one, so it treats every URL as potentially sensitive.
 */
public final class GitRemoteUrlParser {

    private static final Pattern SCP_LIKE = Pattern.compile("^(?:[^@/]+@)?([^:/]+):(.+)$");

    private GitRemoteUrlParser() {
    }

    public static ParsedRemote parse(String remoteUrl) {
        Objects.requireNonNull(remoteUrl, "remoteUrl");
        String trimmed = remoteUrl.strip();

        String host;
        String path;
        if (trimmed.startsWith("ssh://") || trimmed.startsWith("http://")
                || trimmed.startsWith("https://") || trimmed.startsWith("git://")) {
            URI uri;
            try {
                uri = URI.create(trimmed);
            } catch (IllegalArgumentException e) {
                throw new GitLabPublicationException("Could not parse the git remote URL: unrecognised format.");
            }
            host = uri.getHost();
            path = uri.getPath();
        } else {
            Matcher matcher = SCP_LIKE.matcher(trimmed);
            if (!matcher.matches()) {
                throw new GitLabPublicationException("Could not parse the git remote URL: unrecognised format.");
            }
            host = matcher.group(1);
            path = matcher.group(2);
        }

        if (host == null || host.isBlank() || path == null || path.isBlank()) {
            throw new GitLabPublicationException("Could not parse the git remote URL: missing host or path.");
        }

        String normalizedPath = path.strip();
        if (normalizedPath.startsWith("/")) {
            normalizedPath = normalizedPath.substring(1);
        }
        if (normalizedPath.endsWith(".git")) {
            normalizedPath = normalizedPath.substring(0, normalizedPath.length() - ".git".length());
        }
        if (normalizedPath.endsWith("/")) {
            normalizedPath = normalizedPath.substring(0, normalizedPath.length() - 1);
        }

        return new ParsedRemote(host, normalizedPath);
    }
}
