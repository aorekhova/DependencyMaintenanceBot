package com.tungsten.depbot.git;

/** One severity group's branch, created (but never checked out) from the run's shared base SHA. */
public record CreatedBranch(String severity, String branchName) {
}
