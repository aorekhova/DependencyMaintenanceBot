package com.tungsten.depbot.git;

import java.util.Locale;
import java.util.Objects;

/**
 * Names the branch one library's remediation is carried out on.
 *
 * <p>One branch per library, not one per severity. Under the two-phase design each finding gets its own
 * verified source ref, and two findings at the same severity can legitimately belong to different
 * release lines -- so a shared severity branch would have to be cut from one of them and would put the
 * other's work on the wrong base. The run id keeps repeated runs from colliding; the severity is in the
 * name only so a human can see the priority at a glance.
 *
 * <p>Coordinates are sanitised to the characters git accepts in a ref name. A dot is legal and is kept,
 * because {@code com.fasterxml.jackson.core} is far more readable than the same string with the dots
 * replaced -- but a leading dot, a trailing dot, a {@code ..} sequence and a trailing {@code .lock} are
 * all rejected by git and are handled here rather than left to fail at branch-creation time.
 */
public final class RemediationBranchName {

    public static final String PREFIX = "remediation";

    private RemediationBranchName() {
    }

    /**
     * {@code remediation/<runId>/<refSlug>-<shaPrefix>}, one shared branch for every automatically
     * allowed remediation group in this run that verified to the same {@code (verifiedSourceRef,
     * verifiedSourceSha)} pair -- see {@code RemediationCohort}.
     *
     * <p>Both the ref and the SHA are folded into the name, not the SHA alone: two different target
     * refs can temporarily resolve to the same commit, and they still have to end up as two different
     * branches (and, eventually, two different Merge Requests) -- collapsing them because they happen
     * to share a SHA today would be an architectural mistake, not a convenience.
     */
    public static String forRun(String runId, String verifiedSourceRef, String verifiedSourceSha) {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(verifiedSourceRef, "verifiedSourceRef");
        Objects.requireNonNull(verifiedSourceSha, "verifiedSourceSha");

        String shaPrefix = verifiedSourceSha.length() > 12 ? verifiedSourceSha.substring(0, 12) : verifiedSourceSha;
        return PREFIX + "/" + sanitize(runId) + "/" + sanitize(verifiedSourceRef) + "-" + sanitize(shaPrefix);
    }

    /**
     * {@code remediation/<runId>/<refSlug>-<shaPrefix>-candidate/<groupId>}, a throwaway local branch
     * used only while one group's own Implementation/cumulative-Jenkins-validation attempt is in
     * progress.
     *
     * <p>Cut from the cohort's <em>current accepted tip</em> -- {@code cohort.verifiedSourceSha()} (S0)
     * for the first group in the cohort, the previous group's own just-accepted commit for every one
     * after it -- so each group's candidate already contains every previously accepted group's change,
     * which is what makes cumulative validation possible. The {@code verifiedSourceSha} parameter here
     * is therefore this accepted tip, not always the cohort's original S0. Deleted immediately once this
     * group's attempt is resolved, either way: fast-forwarded onto the shared branch on acceptance
     * (see {@code VulnerabilityRemediationService#runCohort}), or discarded on rejection.
     */
    public static String forGroupCandidate(
            String runId, String verifiedSourceRef, String verifiedSourceSha, String groupId) {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(verifiedSourceRef, "verifiedSourceRef");
        Objects.requireNonNull(verifiedSourceSha, "verifiedSourceSha");
        Objects.requireNonNull(groupId, "groupId");

        String shaPrefix = verifiedSourceSha.length() > 12 ? verifiedSourceSha.substring(0, 12) : verifiedSourceSha;
        return PREFIX + "/" + sanitize(runId) + "/" + sanitize(verifiedSourceRef) + "-" + sanitize(shaPrefix)
                + "-candidate/" + sanitize(groupId);
    }

    /**
     * {@code remediation/<runId>/<refSlug>-<shaPrefix>-risky/<groupId>}, the dedicated branch for one
     * {@code HUMAN_REVIEW_REQUIRED} group given its own isolated attempt.
     *
     * <p>Deliberately distinct from {@link #forRun}'s name for the exact same {@code (runId,
     * verifiedSourceRef, verifiedSourceSha)} triple -- an ordinary cohort and a risky group can validly
     * coexist on the same verified ref/SHA in the same run, and must never collapse onto the same
     * branch. Also distinct per {@code groupId}, so two risky groups sharing a ref/SHA never collide with
     * each other either -- each risky group is always alone on its own branch.
     */
    public static String forRiskyGroup(
            String runId, String verifiedSourceRef, String verifiedSourceSha, String groupId) {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(verifiedSourceRef, "verifiedSourceRef");
        Objects.requireNonNull(verifiedSourceSha, "verifiedSourceSha");
        Objects.requireNonNull(groupId, "groupId");

        String shaPrefix = verifiedSourceSha.length() > 12 ? verifiedSourceSha.substring(0, 12) : verifiedSourceSha;
        return PREFIX + "/" + sanitize(runId) + "/" + sanitize(verifiedSourceRef) + "-" + sanitize(shaPrefix)
                + "-risky/" + sanitize(groupId);
    }

    /**
     * {@code remediation/<runId>/<severity>/<groupId>__<artifactId>}
     *
     * @deprecated superseded by {@link #forRun}: every automatic remediation group in a run now lands on
     *             one shared branch per verified source ref, not its own branch. Retained only because
     *             it is not yet known whether the legacy {@code prepare-remediation-branches} command
     *             still depends on this exact naming.
     */
    @Deprecated
    public static String forLibrary(String runId, String severity, String groupId, String artifactId) {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(groupId, "groupId");
        Objects.requireNonNull(artifactId, "artifactId");

        return PREFIX + "/" + sanitize(runId) + "/" + sanitize(severity.toLowerCase(Locale.ROOT)) + "/"
                + sanitize(groupId) + "__" + sanitize(artifactId);
    }

    /**
     * {@code remediation/<runId>/<severity>/<remediation group id>}
     *
     * @deprecated superseded by {@link #forRun}, for the same reason as {@link #forLibrary}: a group no
     *             longer gets its own branch, a whole run's worth of automatic groups for one verified
     *             ref shares one.
     */
    @Deprecated
    public static String forGroup(String runId, String severity, String groupId) {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(groupId, "groupId");

        return PREFIX + "/" + sanitize(runId) + "/" + sanitize(severity.toLowerCase(Locale.ROOT)) + "/"
                + sanitize(groupId);
    }

    /**
     * One path component, reduced to something git will accept: word characters, dots and hyphens, with
     * every git-illegal shape neutralised.
     */
    static String sanitize(String value) {
        String cleaned = value.replaceAll("[^A-Za-z0-9._-]", "_");

        // ".." is illegal anywhere in a ref name. A whole run of dots collapses to one separator, rather
        // than being replaced pair by pair -- "a....b" should read "a_b", not "a__b".
        cleaned = cleaned.replaceAll("\\.{2,}", "_");
        // A component may not begin or end with a dot, and may not end with ".lock".
        cleaned = cleaned.replaceAll("^\\.+", "_").replaceAll("\\.+$", "_");
        if (cleaned.toLowerCase(Locale.ROOT).endsWith(".lock")) {
            cleaned = cleaned.substring(0, cleaned.length() - ".lock".length()) + "_lock";
        }
        return cleaned.isEmpty() ? "_" : cleaned;
    }
}
