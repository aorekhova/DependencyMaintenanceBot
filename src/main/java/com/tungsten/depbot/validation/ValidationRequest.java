package com.tungsten.depbot.validation;

import java.nio.file.Path;
import java.util.Objects;

/**
 * What the gate is being asked to check: the working tree as the implementation left it, and which
 * artifact version must no longer be what resolves.
 *
 * <p>{@code vulnerableVersion} is the version the finding was raised against, taken from the assessment's
 * own observation where it made one and from Mend's report otherwise. It may be {@code null} -- a
 * remediation that removed a transitive arrival entirely, or one where no version was ever established --
 * and the gate then checks only that the build model still resolves, which is still worth knowing.
 */
public record ValidationRequest(
        Path workspace,
        String groupId,
        String artifactId,
        String vulnerableVersion) {

    public ValidationRequest {
        Objects.requireNonNull(workspace, "workspace");
        Objects.requireNonNull(groupId, "groupId");
        Objects.requireNonNull(artifactId, "artifactId");
    }

    public String coordinates() {
        return groupId + ":" + artifactId;
    }

    public boolean hasVulnerableVersion() {
        return vulnerableVersion != null && !vulnerableVersion.isBlank();
    }
}
