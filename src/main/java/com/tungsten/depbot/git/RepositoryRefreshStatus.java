package com.tungsten.depbot.git;

/** Whether {@link ManagedRepositoryRefresher} managed to bring the checkout to its remote counterpart. */
public enum RepositoryRefreshStatus {
    REFRESHED,
    FAILED
}
