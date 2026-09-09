package com.tungsten.depbot.jenkins;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.Objects;

/**
 * A build this application triggered, at whatever point its identity is known.
 *
 * <p>{@code buildNumber}/{@code buildUrl} are {@code null} until the build's identity is actually known
 * -- persisted as soon as either {@code queueItemUrl} or the legacy-fallback fields are known (see
 * {@code JenkinsValidationService}'s own {@code jenkins-trigger.json}), so a retry after the process is
 * interrupted mid-poll resumes reading rather than triggering a second build.
 *
 * <p>Exactly one of two discovery modes is ever in play for a given ref, decided once, at trigger time,
 * by {@link JenkinsApiClient} alone (never re-decided later):
 *
 * <ul>
 *   <li><strong>Queue-item mode</strong> ({@code queueItemUrl} set, legacy fields {@code null}) -- the
 *       normal, documented Jenkins Remote API shape: the trigger response's {@code Location} pointed at
 *       an actual {@code queue/item/<id>/}, which resolves into {@code executable.number}/{@code
 *       executable.url} by polling that queue item.</li>
 *   <li><strong>Legacy fallback mode</strong> ({@code queueItemUrl} {@code null}, legacy fields set) --
 *       confirmed against the real Jenkins 2.204.2 installation: a multipart trigger carrying a core File
 *       Parameter ({@code SOURCE_PATCH}) is handled by Jenkins's classic, form-submission-shaped {@code
 *       doBuild} path rather than the queue-item REST path, and its {@code Location} redirects back to
 *       the job's own page -- even though the build was genuinely, successfully queued and later run.
 *       {@code legacyFallbackFromBuildNumber} is the job's {@code nextBuildNumber} read <em>immediately
 *       before</em> the trigger request was sent; {@code legacyExpectedBaselineSha}/
 *       {@code legacyExpectedTreeSha} are this candidate's own {@code BASE_COMMIT_SHA}/
 *       {@code EXPECTED_TREE_SHA}, used to positively identify -- never merely guess -- which of the
 *       job's new builds is actually this trigger's own, by matching its own build parameters.</li>
 * </ul>
 */
public record JenkinsBuildRef(
        String queueItemUrl,
        Integer buildNumber,
        String buildUrl,
        Integer legacyFallbackFromBuildNumber,
        String legacyExpectedBaselineSha,
        String legacyExpectedTreeSha) {

    public JenkinsBuildRef {
        boolean queueItemMode = queueItemUrl != null;
        boolean legacyMode = legacyFallbackFromBuildNumber != null;
        if (queueItemMode == legacyMode) {
            throw new IllegalArgumentException(
                    "a JenkinsBuildRef must be in exactly one discovery mode: either queueItemUrl "
                            + "(queue-item mode) or legacyFallbackFromBuildNumber (legacy fallback mode), never both "
                            + "or neither");
        }
        if (legacyMode) {
            Objects.requireNonNull(legacyExpectedBaselineSha, "legacyExpectedBaselineSha");
            Objects.requireNonNull(legacyExpectedTreeSha, "legacyExpectedTreeSha");
        }
    }

    public static JenkinsBuildRef queueItem(String queueItemUrl) {
        return new JenkinsBuildRef(queueItemUrl, null, null, null, null, null);
    }

    public static JenkinsBuildRef legacyFallback(
            int fallbackFromBuildNumber, String expectedBaselineSha, String expectedTreeSha) {
        return new JenkinsBuildRef(null, null, null, fallbackFromBuildNumber, expectedBaselineSha, expectedTreeSha);
    }

    /** As this ref, but with the build's identity now known -- keeps whichever discovery mode it started in. */
    public JenkinsBuildRef withResolvedBuild(int buildNumber, String buildUrl) {
        return new JenkinsBuildRef(queueItemUrl, buildNumber, buildUrl,
                legacyFallbackFromBuildNumber, legacyExpectedBaselineSha, legacyExpectedTreeSha);
    }

    /**
     * {@code @JsonIgnore} is load-bearing, not decorative: without it, Jackson's record handling treats
     * this {@code isXxx}-named derived method as an extra virtual property named {@code legacyFallback}
     * on serialization -- which then fails to deserialize back, since it matches none of the six actual
     * canonical components. This surfaced as a real bug: {@code JenkinsValidationService}'s own {@code
     * jenkins-trigger.json} round trip broke the moment this method existed, in both production code and
     * this class's own tests, until this annotation was added.
     */
    @JsonIgnore
    public boolean isLegacyFallback() {
        return legacyFallbackFromBuildNumber != null;
    }
}
