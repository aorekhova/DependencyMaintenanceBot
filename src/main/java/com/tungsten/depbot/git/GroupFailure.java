package com.tungsten.depbot.git;

/** A severity group whose branch or worktree could not be created, and why. */
public record GroupFailure(String group, String message) {
}
