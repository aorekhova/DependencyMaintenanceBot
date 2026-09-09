package com.tungsten.depbot.publication;

import java.util.Objects;

/** What GitLab itself says about the configured project -- read-only ground truth, never assumed. */
public record ProjectMetadata(String id, String pathWithNamespace, String webUrl) {

    public ProjectMetadata {
        Objects.requireNonNull(pathWithNamespace, "pathWithNamespace");
    }
}
