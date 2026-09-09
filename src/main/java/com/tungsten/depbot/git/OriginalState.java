package com.tungsten.depbot.git;

/**
 * The checkout's state before a run touched anything, captured so it can be restored afterward.
 *
 * <p>{@code branchName} is {@code null} when {@code detached} is {@code true} -- there was no
 * branch to remember, only a commit.
 */
public record OriginalState(String branchName, String headSha, boolean detached) {
}
