package com.tungsten.depbot.remediation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses Mend's free-text {@code fixResolution} strings for the version they recommend for one
 * exact {@code groupId:artifactId} -- and only that artifact.
 *
 * <p>A single {@code fixResolution} string is a comma-separated mix of proper Maven coordinates
 * for the affected artifact <em>and its siblings</em>, plus git-repository references such as
 * {@code "https://github.com/bcgit/bc-java.git - r1rv85"}. Matching is done by searching for the
 * literal {@code groupId:artifactId:} prefix rather than splitting on commas, so a sibling
 * coordinate or a URL (which has only one colon, in its scheme) is never mistaken for a match.
 *
 * <p>"Stable" means a version made only of digits and dots ({@code ^[0-9]+(\.[0-9]+)*$}). That is
 * a stricter test than just excluding {@code beta}/{@code rc}/{@code alpha}/{@code SNAPSHOT}: any
 * other qualifier this project has not anticipated also fails it, which is the safe direction to
 * err in -- treating an unknown qualifier as unstable can only lead to a conservative
 * {@code MANUAL_ANALYSIS_REQUIRED}, never to a wrong recommendation.
 *
 * <p><strong>{@link #resolve} never recommends a downgrade.</strong> Mend routinely lists fix
 * versions from several parallel release branches for the same {@code groupId:artifactId} (for
 * example {@code 2.18.9}, {@code 2.21.5} and {@code 2.22.1} for one Jackson CVE, each the fixed
 * version of a different maintained branch) with no indication in the data of which branch the
 * project is actually on. Picking the numeric minimum of those without comparing against the
 * project's current version can select a fix from an older branch than the one already installed
 * -- an actual downgrade. {@link #resolve} therefore discards every candidate that is not strictly
 * greater than the current version before picking the smallest of what remains.
 */
public final class TargetVersionResolver {

    public static final String MANUAL_ANALYSIS_REQUIRED = "MANUAL_ANALYSIS_REQUIRED";

    private static final Pattern STABLE_VERSION = Pattern.compile("^[0-9]+(\\.[0-9]+)*$");

    private TargetVersionResolver() {
    }

    /** Every version this one {@code fixResolution} string recommends for the exact artifact. */
    public static List<String> extractVersions(String groupId, String artifactId, String fixResolution) {
        List<String> found = new ArrayList<>();
        if (isBlank(fixResolution) || isBlank(groupId) || isBlank(artifactId)) {
            return found;
        }

        // Negative lookbehind stops "xorg.foo:bar:1.0" matching a search for "org.foo:bar:".
        Pattern coordinate = Pattern.compile(
                "(?<![\\w.])" + Pattern.quote(groupId) + ":" + Pattern.quote(artifactId) + ":([\\w.\\-]+)");
        Matcher matcher = coordinate.matcher(fixResolution);
        while (matcher.find()) {
            found.add(matcher.group(1));
        }
        return found;
    }

    public static boolean isStable(String version) {
        return version != null && STABLE_VERSION.matcher(version).matches();
    }

    /**
     * The stable candidate versions one finding's fix text (its top fix plus every alternative fix)
     * offers for the exact artifact.
     */
    public static Set<String> stableCandidatesForFinding(
            String groupId, String artifactId, List<String> fixResolutionsOfOneFinding) {
        Set<String> candidates = new LinkedHashSet<>();
        for (String fixResolution : fixResolutionsOfOneFinding) {
            for (String version : extractVersions(groupId, artifactId, fixResolution)) {
                if (isStable(version)) {
                    candidates.add(version);
                }
            }
        }
        return candidates;
    }

    /**
     * Every version that appears in <em>every</em> finding's stable candidate set -- i.e. is
     * confirmed to close every CVE affecting this library, not just some of them. Empty when there
     * is no such version at all: a finding had no stable candidate, or the findings' recommendations
     * conflict and no single version closes all of them.
     *
     * <p>Exposed (not just an implementation detail of {@link #resolve}) so a caller that gets
     * {@link #MANUAL_ANALYSIS_REQUIRED} back from {@code resolve} can tell two very different
     * situations apart: no consistent fix exists at all (this set is empty), versus a consistent
     * fix exists but only as a downgrade (this set is non-empty, every member is at or below
     * {@code currentVersion}).
     */
    public static Set<String> intersectionOf(List<Set<String>> stableCandidatesPerFinding) {
        if (stableCandidatesPerFinding.isEmpty()) {
            return Set.of();
        }

        Set<String> intersection = null;
        for (Set<String> candidates : stableCandidatesPerFinding) {
            if (candidates.isEmpty()) {
                return Set.of();
            }
            if (intersection == null) {
                intersection = new LinkedHashSet<>(candidates);
            } else {
                intersection.retainAll(candidates);
            }
        }
        return intersection == null ? Set.of() : intersection;
    }

    /**
     * Resolves one library's target version from every one of its findings' stable candidate sets.
     *
     * <p>A version only counts as "the" target if it appears in <em>every</em> finding's candidate
     * set (see {@link #intersectionOf}) <em>and</em> is strictly greater than {@code currentVersion}.
     * Among those, the smallest is chosen: the minimal upgrade that is still fully safe. Versions
     * from a candidate set are never treated as a sequential upgrade path across release branches --
     * a fix backported to an older branch (for example {@code 2.18.9} when the project is already on
     * {@code 2.22.0}) is exactly as ineligible as the current version itself, because installing it
     * would be a downgrade, not an upgrade, regardless of what CVEs it also happens to close.
     *
     * <p>Falls back to {@link #MANUAL_ANALYSIS_REQUIRED} when {@link #intersectionOf} is empty (no
     * single version is confirmed to close every CVE at all), or when it is non-empty but every
     * member is at or below {@code currentVersion} (a consistent fix exists, but only as a
     * downgrade) -- this method never recommends installing a version the project is already past.
     */
    public static String resolve(List<Set<String>> stableCandidatesPerFinding, String currentVersion) {
        Set<String> intersection = intersectionOf(stableCandidatesPerFinding);
        if (intersection.isEmpty()) {
            return MANUAL_ANALYSIS_REQUIRED;
        }

        List<String> forward = new ArrayList<>();
        for (String candidate : intersection) {
            if (isForward(candidate, currentVersion)) {
                forward.add(candidate);
            }
        }
        if (forward.isEmpty()) {
            return MANUAL_ANALYSIS_REQUIRED;
        }
        return Collections.min(forward, TargetVersionResolver::compareVersions);
    }

    /** Whether {@code candidate} is a real upgrade over {@code currentVersion} -- strictly greater, never equal. */
    private static boolean isForward(String candidate, String currentVersion) {
        return isBlank(currentVersion) || compareVersions(candidate, currentVersion) > 0;
    }

    /**
     * Best-effort dotted-segment comparison (e.g. {@code "1.85"} vs {@code "1.9"}): each segment is
     * compared numerically when both sides are pure digits, otherwise as plain strings. Not a full
     * semver parser -- it only needs to order the stable, dots-and-digits versions {@link #isStable}
     * already let through.
     */
    static int compareVersions(String a, String b) {
        String[] partsA = a.split("\\.");
        String[] partsB = b.split("\\.");
        int length = Math.max(partsA.length, partsB.length);
        for (int i = 0; i < length; i++) {
            String segmentA = i < partsA.length ? partsA[i] : "0";
            String segmentB = i < partsB.length ? partsB[i] : "0";
            int comparison = compareSegment(segmentA, segmentB);
            if (comparison != 0) {
                return comparison;
            }
        }
        return 0;
    }

    private static int compareSegment(String a, String b) {
        if (a.matches("[0-9]+") && b.matches("[0-9]+")) {
            return Integer.compare(Integer.parseInt(a), Integer.parseInt(b));
        }
        return a.compareTo(b);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
