package com.tungsten.depbot.validation;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * The minimal local gate: resolve the dependency tree offline and see what the artifact actually resolves
 * to now.
 *
 * <p>Two things are being asked, and both are cheap:
 *
 * <ol>
 *   <li><strong>Does the build model still resolve at all?</strong> A malformed POM, a version that does
 *       not exist, a BOM import that cannot be found, a property left dangling -- every one of those makes
 *       {@code dependency:tree} exit non-zero. This is the check that catches a change which is
 *       structurally broken however confidently it was reported as complete.</li>
 *   <li><strong>Is the vulnerable version still what resolves?</strong> If it is, the remediation did not
 *       take effect, whatever the report says. This is the check the jackson-databind pilot never had: it
 *       is the difference between "an agent said it upgraded the library" and "the library is upgraded".</li>
 * </ol>
 *
 * <p>Deliberately not a build and not a test run. {@code -o} keeps it offline and {@code -B}
 * non-interactive; {@code compile}, {@code test}, {@code package} and {@code install} are never invoked.
 * Passing here does not mean the project compiles -- which is why the status a commit gets is still
 * {@code COMMITTED_PENDING_VALIDATION}. It means the change is not <em>knowably</em> wrong.
 *
 * <p>A tree that comes back empty is a pass. That is correct rather than lenient: a remediation that
 * removed a transitive arrival, or excluded it, legitimately leaves the artifact resolving nowhere.
 */
public final class DependencyResolutionGate implements RemediationValidationGate {

    /**
     * Generous on purpose. Resolving a dozen modules offline took the better part of a minute in the first
     * real pilot, and a gate that times out is refused -- so the budget has to be well clear of normal.
     */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofMinutes(15);

    private final Duration timeout;

    public DependencyResolutionGate() {
        this(DEFAULT_TIMEOUT);
    }

    public DependencyResolutionGate(Duration timeout) {
        this.timeout = Objects.requireNonNull(timeout, "timeout");
    }

    @Override
    public ValidationOutcome validate(ValidationRequest request) {
        Objects.requireNonNull(request, "request");

        Path workspace = request.workspace();
        List<String> command = List.of(
                MavenInvocation.executableFor(workspace),
                "-o",
                "-B",
                "dependency:tree",
                "-Dincludes=" + request.coordinates());

        MavenInvocation.Result result = MavenInvocation.run(workspace, command, timeout);

        if (!result.started()) {
            return ValidationOutcome.notRun(
                    "The dependency tree could not be resolved because Maven could not be started, so "
                            + "whether this change is sound is unknown. " + result.failureMessage(),
                    command, result.output());
        }
        if (result.exitCode() == null) {
            return ValidationOutcome.notRun(
                    "The dependency tree did not finish, so whether this change is sound is unknown. "
                            + result.failureMessage(),
                    command, result.output());
        }
        if (result.exitCode() != 0) {
            return ValidationOutcome.failed(
                    "The build model no longer resolves: Maven exited with code " + result.exitCode()
                            + " resolving the dependency tree. Whatever else the change did, the project "
                            + "cannot resolve its dependencies in this state.",
                    command, result.output());
        }

        if (!request.hasVulnerableVersion()) {
            return ValidationOutcome.passed(
                    "The build model resolves. No vulnerable version was established for "
                            + request.coordinates() + ", so nothing further could be checked here.",
                    command, result.output());
        }

        Set<String> resolved = resolvedVersionsOf(
                result.output(), request.groupId(), request.artifactId());

        if (resolved.contains(request.vulnerableVersion())) {
            return ValidationOutcome.failed(
                    request.coordinates() + " still resolves to " + request.vulnerableVersion()
                            + ", the version the finding was raised against, so the remediation did not "
                            + "take effect. Resolved: " + String.join(", ", resolved) + ".",
                    command, result.output());
        }

        String what = resolved.isEmpty()
                ? request.coordinates() + " no longer resolves at all, so the vulnerable version is gone"
                : request.coordinates() + " now resolves to " + String.join(", ", resolved)
                        + ", no longer " + request.vulnerableVersion();
        // Only a single, unambiguous answer is ever recorded structurally -- an empty tree (nothing
        // resolves) or more than one distinct version across a multi-module tree both mean there is no
        // one version to safely name as "the" resolved version.
        String resolvedVersion = resolved.size() == 1 ? resolved.iterator().next() : null;
        return ValidationOutcome.passed("The build model resolves and " + what + ".", command,
                result.output(), resolvedVersion);
    }

    /**
     * Every version {@code groupId:artifactId} resolves to in the tree output.
     *
     * <p>Parsed from the coordinate token rather than by searching for the version string on its own: a
     * bare search for {@code 1.84} would match {@code 1.840}, another artifact's version, a timestamp or a
     * path, and a false "still vulnerable" is as damaging here as a false pass. Maven prints
     * {@code groupId:artifactId:packaging[:classifier]:version[:scope]}, so the version is the token
     * before the scope -- located by anchoring on the coordinate prefix and counting from there.
     */
    static Set<String> resolvedVersionsOf(String treeOutput, String groupId, String artifactId) {
        Set<String> versions = new LinkedHashSet<>();
        String prefix = groupId + ":" + artifactId + ":";

        for (String line : treeOutput.split("\\R")) {
            int start = line.indexOf(prefix);
            while (start >= 0) {
                // Reject a partial match such as "xorg.example:lib:" when looking for "org.example:lib:".
                if (start == 0 || !isCoordinateCharacter(line.charAt(start - 1))) {
                    String version = versionAfter(line, start + prefix.length());
                    if (version != null) {
                        versions.add(version);
                    }
                }
                start = line.indexOf(prefix, start + 1);
            }
        }
        return versions;
    }

    /**
     * The version out of the segments following the coordinate prefix: {@code packaging:version} or
     * {@code packaging:classifier:version}, each possibly followed by a scope. Maven's own ordering puts
     * the version immediately before the scope when there is one and last when there is not.
     */
    private static String versionAfter(String line, int from) {
        List<String> segments = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (int i = from; i < line.length(); i++) {
            char character = line.charAt(i);
            if (character == ':') {
                segments.add(current.toString());
                current.setLength(0);
            } else if (isCoordinateCharacter(character)) {
                current.append(character);
            } else {
                break;
            }
        }
        segments.add(current.toString());

        // packaging is always first; anything after it that is not a known scope is the version, and the
        // last such segment is the version whichever optional parts were present.
        String version = null;
        for (int i = 1; i < segments.size(); i++) {
            String segment = segments.get(i);
            if (!segment.isEmpty() && !isScope(segment)) {
                version = segment;
            }
        }
        return version;
    }

    private static boolean isScope(String segment) {
        return switch (segment) {
            case "compile", "provided", "runtime", "test", "system", "import" -> true;
            default -> false;
        };
    }

    private static boolean isCoordinateCharacter(char character) {
        return Character.isLetterOrDigit(character) || character == '.' || character == '-'
                || character == '_' || character == '+';
    }
}
