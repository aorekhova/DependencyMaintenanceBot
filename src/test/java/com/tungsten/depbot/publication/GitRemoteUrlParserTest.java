package com.tungsten.depbot.publication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class GitRemoteUrlParserTest {

    @Test
    @DisplayName("SCP-like SSH syntax parses to host and path")
    void scpLikeSsh() {
        ParsedRemote parsed = GitRemoteUrlParser.parse("git@gitlab.example.com:group/project.git");
        assertEquals("gitlab.example.com", parsed.host());
        assertEquals("group/project", parsed.path());
    }

    @Test
    @DisplayName("ssh:// syntax parses to host and path")
    void sshScheme() {
        ParsedRemote parsed = GitRemoteUrlParser.parse("ssh://git@gitlab.example.com:2222/group/project.git");
        assertEquals("gitlab.example.com", parsed.host());
        assertEquals("group/project", parsed.path());
    }

    @Test
    @DisplayName("https:// syntax parses to host and path")
    void httpsScheme() {
        ParsedRemote parsed = GitRemoteUrlParser.parse("https://gitlab.example.com/group/project.git");
        assertEquals("gitlab.example.com", parsed.host());
        assertEquals("group/project", parsed.path());
    }

    @Test
    @DisplayName("https:// without a trailing .git still parses correctly")
    void httpsSchemeWithoutDotGit() {
        ParsedRemote parsed = GitRemoteUrlParser.parse("https://gitlab.example.com/group/project");
        assertEquals("gitlab.example.com", parsed.host());
        assertEquals("group/project", parsed.path());
    }

    @Test
    @DisplayName("an embedded credential in an https URL never appears in the parsed path or an exception")
    void embeddedCredentialNeverLeaks() {
        ParsedRemote parsed = GitRemoteUrlParser.parse("https://oauth2:SECRET-TOKEN@gitlab.example.com/group/project.git");
        assertEquals("gitlab.example.com", parsed.host());
        assertEquals("group/project", parsed.path());
    }

    @Test
    @DisplayName("nested group paths are preserved in full")
    void nestedGroupPath() {
        ParsedRemote parsed = GitRemoteUrlParser.parse("git@gitlab.example.com:group/subgroup/project.git");
        assertEquals("group/subgroup/project", parsed.path());
    }

    @Test
    @DisplayName("an unrecognisable URL throws, without ever including the raw URL in the message")
    void unrecognisableUrlThrowsSafely() {
        GitLabPublicationException exception = assertThrows(GitLabPublicationException.class,
                () -> GitRemoteUrlParser.parse("not a url at all, no colon or slash"));
        assertEquals(false, exception.getMessage().contains("not a url at all"));
    }
}
