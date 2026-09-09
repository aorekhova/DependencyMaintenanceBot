package com.tungsten.depbot.jenkins;

import java.util.Objects;

/**
 * The exact candidate one Jenkins validation attempt is about: the job's own three parameters
 * ({@code BASE_COMMIT_SHA}, {@code SOURCE_PATCH}, {@code EXPECTED_TREE_SHA}), bundled together so a
 * persisted attempt can be compared, field by field, against a freshly-requested one before its result
 * is ever reused (see {@code JenkinsValidationService}'s identity-aware idempotency).
 */
public record JenkinsCandidate(String baselineSha, String candidateSha, String sourcePatch, String expectedTreeSha) {

    public JenkinsCandidate {
        Objects.requireNonNull(baselineSha, "baselineSha");
        Objects.requireNonNull(candidateSha, "candidateSha");
        Objects.requireNonNull(sourcePatch, "sourcePatch");
        Objects.requireNonNull(expectedTreeSha, "expectedTreeSha");
    }

    /** Whether {@code other} is about the exact same commit pair and expected tree as this one. */
    public boolean sameIdentity(JenkinsCandidate other) {
        return other != null
                && baselineSha.equals(other.baselineSha())
                && candidateSha.equals(other.candidateSha())
                && expectedTreeSha.equals(other.expectedTreeSha());
    }
}
