package com.tungsten.depbot.git;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Establishes, independently of the assessment, whether the ref it named exists -- and what commit it
 * is actually at.
 *
 * <p>This is the boundary where a model's claim becomes a fact. The assessment reports a ref and,
 * usually, a SHA it believes that ref is at; <strong>the SHA is never used.</strong> A
 * model-supplied SHA is a plausible-looking forty-character string that nothing verified, and
 * branching from one would put remediation work on an arbitrary commit -- possibly on a different
 * branch, possibly on nothing at all. Only what git resolves here is ever branched from.
 *
 * <p>Verification is deliberately stricter than "does {@code rev-parse} produce a commit". It requires
 * the name to be an <em>actual ref</em>, present in {@code git for-each-ref}. {@code master~5},
 * {@code HEAD@\{1\}} and {@code origin/master^2} all resolve to real commits, and none of them is a
 * branch anyone chose to maintain; a remediation branch cut from one would be based on a commit with
 * no relationship to any release line. Revision syntax is therefore rejected outright rather than
 * quietly resolved.
 *
 * <p>An ambiguous short name -- a branch and a tag that shorten to the same thing -- is also rejected.
 * Picking either one would be a coin toss over which commit a security fix gets based on.
 */
public final class SourceRefVerifier {

    /**
     * Characters and sequences that mean the name is a revision expression, a glob, or simply not a
     * valid ref name: git's own {@code check-ref-format} rules plus the revision operators.
     */
    private static final Pattern NOT_A_PLAIN_REF_NAME = Pattern.compile(
            "[~^:?*\\[\\\\\\s]|@\\{|\\.\\.");

    private static final List<String> SHORTENABLE_PREFIXES =
            List.of("refs/remotes/", "refs/heads/", "refs/tags/");

    private final GitCommandRunner git;

    public SourceRefVerifier(GitCommandRunner git) {
        this.git = Objects.requireNonNull(git, "git");
    }

    /**
     * @param requestedRef the ref the assessment named, for example {@code origin/release/9.2}
     * @param claimedSha   the SHA the assessment claimed, recorded for comparison and never used
     */
    public SourceRefVerification verify(Path repoPath, String requestedRef, String claimedSha) {
        Objects.requireNonNull(repoPath, "repoPath");

        if (requestedRef == null || requestedRef.isBlank()) {
            return SourceRefVerification.rejected(requestedRef, claimedSha,
                    "The assessment named no source ref, so there is nothing to verify or branch from.");
        }

        String ref = requestedRef.strip();
        if (ref.startsWith("-")) {
            return SourceRefVerification.rejected(requestedRef, claimedSha,
                    "\"" + ref + "\" starts with a dash, which git would read as an option rather than a ref.");
        }
        if (NOT_A_PLAIN_REF_NAME.matcher(ref).find()) {
            return SourceRefVerification.rejected(requestedRef, claimedSha,
                    "\"" + ref + "\" is not a plain ref name -- it contains revision or glob syntax. A "
                            + "remediation branch is only ever created from a ref that genuinely exists, "
                            + "never from a computed revision.");
        }

        List<String> matches = matchingRefs(repoPath, ref);
        if (matches.isEmpty()) {
            return SourceRefVerification.rejected(requestedRef, claimedSha,
                    "No ref named \"" + ref + "\" exists in this repository, so the assessment's conclusion "
                            + "cannot be acted on. Remote refs were refreshed before the assessment ran.");
        }
        if (matches.size() > 1) {
            return SourceRefVerification.rejected(requestedRef, claimedSha,
                    "\"" + ref + "\" is ambiguous -- it matches " + String.join(", ", matches)
                            + ". Which commit a security fix is based on cannot be left to a guess.");
        }

        String resolvedRef = matches.get(0);
        String resolvedSha;
        try {
            resolvedSha = git.revParseCommit(repoPath, resolvedRef);
        } catch (GitCommandException e) {
            return SourceRefVerification.rejected(requestedRef, claimedSha,
                    "\"" + resolvedRef + "\" exists but does not resolve to a commit: " + e.getMessage());
        }
        if (resolvedSha.isBlank()) {
            return SourceRefVerification.rejected(requestedRef, claimedSha,
                    "\"" + resolvedRef + "\" resolved to nothing.");
        }

        return SourceRefVerification.verified(requestedRef, resolvedRef, resolvedSha, claimedSha);
    }

    /**
     * Every existing ref whose full or shortened name is exactly {@code ref}. More than one means the
     * name is ambiguous; the full name always matches at most one ref.
     */
    private List<String> matchingRefs(Path repoPath, String ref) {
        Map<String, List<String>> byShortName = new LinkedHashMap<>();
        List<String> matches = new ArrayList<>();

        for (String line : git.listRefs(repoPath).split("\\R")) {
            String fullName = line.strip();
            if (fullName.isEmpty()) {
                continue;
            }
            if (fullName.equals(ref)) {
                return List.of(fullName);
            }
            byShortName.computeIfAbsent(shorten(fullName), ignored -> new ArrayList<>()).add(fullName);
        }

        List<String> shortMatches = byShortName.get(ref);
        if (shortMatches != null) {
            matches.addAll(shortMatches);
        }
        return matches;
    }

    private static String shorten(String fullRefName) {
        for (String prefix : SHORTENABLE_PREFIXES) {
            if (fullRefName.startsWith(prefix)) {
                return fullRefName.substring(prefix.length());
            }
        }
        return fullRefName;
    }
}
