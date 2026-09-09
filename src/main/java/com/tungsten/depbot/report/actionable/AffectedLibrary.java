package com.tungsten.depbot.report.actionable;

/**
 * The library a finding affects.
 *
 * <p>{@code coordinates} is the convenience form {@code groupId:artifactId:version}, populated
 * only when all three parts are genuinely present. It is never assembled from partial data,
 * because a half-built coordinate would look authoritative while being wrong — and a developer or
 * an automated remediation step could act on it.
 *
 * <p>Every field is optional; Mend may omit any of them.
 */
public record AffectedLibrary(
        String groupId,
        String artifactId,
        String version,
        String coordinates,
        String name,
        String filename,
        String type,
        String sha1,
        String keyUuid,
        String architecture,
        String languageVersion,
        String description) {
}
