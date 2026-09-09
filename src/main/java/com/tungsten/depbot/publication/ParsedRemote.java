package com.tungsten.depbot.publication;

/** A git remote URL, reduced to the two facts {@link RemoteIdentityVerifier} needs: host and project path. */
public record ParsedRemote(String host, String path) {
}
