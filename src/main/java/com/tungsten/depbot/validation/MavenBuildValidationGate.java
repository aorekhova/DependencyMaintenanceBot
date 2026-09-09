package com.tungsten.depbot.validation;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The pilot's second gate: an actual local build of the project, on the branch an implementation just
 * committed to.
 *
 * <p>Where {@link DependencyResolutionGate} asks one narrow, cheap question offline ("does the
 * vulnerable version still resolve"), this asks the expensive, honest one: does {@code mvn -B clean
 * package} succeed on this branch, right now. It is deliberately dependency-agnostic -- it knows nothing
 * about which library changed, only whether the build did. That is what keeps it from becoming a
 * library-specific workaround: the same command runs whether the commit touched a version property, a
 * BOM, or a dozen source files.
 *
 * <p><strong>{@code package}, not {@code test} or {@code verify}.</strong> On the real project this gate
 * validates, {@code test} alone is not a reliable full check of the multi-module reactor: the test
 * phase does not always force the upstream artifact a classifier-scoped dependency (for example a
 * {@code gwt-client-scripts} classifier) needs to have been built first. {@code package} -- compile,
 * test, and package every reactor module -- has been confirmed to work reliably; {@code verify} is not
 * used because an unfamiliar project's own {@code pom.xml} could bind arbitrary plugins to that phase
 * that this bot has no visibility into and no business triggering.
 *
 * <p><strong>{@code clean}, always.</strong> Without it, Maven's own incremental compiler happily leaves
 * {@code target/} classes from a previous build in place and reports them "up to date" against the new
 * dependency versions this attempt just committed -- exactly the shape of a real production incident
 * (pilot {@code 20260908-220923-771c06}): every successful group's own full-build log was full of
 * {@code Nothing to compile - all classes are up to date}, so a genuine API/linkage incompatibility
 * introduced by the version bump could pass this gate without ever having been recompiled against it.
 * {@code clean} is prepended precisely so this gate always compiles from nothing, on every run.
 *
 * <p><strong>Deliberately online, unlike the dependency-resolution gate.</strong> A remediation may move
 * to a dependency version that is not yet cached locally or mirrored internally; forcing {@code -o}
 * here would risk a false {@code FAILED} for an otherwise correct remediation.
 *
 * <p>A failing build here is never grounds to undo the commit -- see {@code RemediationImplementationService}.
 * This gate only answers one question; what happens to the answer is entirely its caller's decision.
 */
public final class MavenBuildValidationGate implements FullBuildValidationGate {

    /**
     * The exact arguments this gate always runs, after the executable itself -- the single source of
     * truth every human-facing description of "what the full build gate runs" (progress text, console
     * notes, manual reproduction recipes) reads from, so none of them can drift from what {@link #validate}
     * actually invokes.
     */
    public static final List<String> BUILD_ARGS = List.of("-B", "clean", "package");

    /**
     * A full build across an unfamiliar multi-module reactor takes real time -- comfortably longer than
     * the dependency-resolution gate's 15 minutes, since that gate only resolves a tree while this one
     * compiles, tests and packages every module.
     */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofMinutes(45);

    /** How often progress is reported while the build is still running. */
    public static final Duration DEFAULT_HEARTBEAT_INTERVAL = Duration.ofSeconds(30);

    private final Duration timeout;
    private final Duration heartbeatInterval;

    public MavenBuildValidationGate() {
        this(DEFAULT_TIMEOUT, DEFAULT_HEARTBEAT_INTERVAL);
    }

    public MavenBuildValidationGate(Duration timeout) {
        this(timeout, DEFAULT_HEARTBEAT_INTERVAL);
    }

    /** @param heartbeatInterval exposed mainly so a test can avoid waiting on the production default */
    public MavenBuildValidationGate(Duration timeout, Duration heartbeatInterval) {
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        this.heartbeatInterval = Objects.requireNonNull(heartbeatInterval, "heartbeatInterval");
    }

    @Override
    public ValidationOutcome validate(ValidationRequest request, Runnable heartbeat) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(heartbeat, "heartbeat");

        Path workspace = request.workspace();
        List<String> command = new ArrayList<>();
        command.add(MavenInvocation.executableFor(workspace));
        command.addAll(BUILD_ARGS);

        MavenInvocation.Result result =
                MavenInvocation.run(workspace, command, timeout, heartbeatInterval, heartbeat);

        if (!result.started()) {
            return ValidationOutcome.notRun(
                    "The full build could not be run because Maven could not be started, so whether "
                            + "this change actually builds is unknown. " + result.failureMessage(),
                    command, result.output());
        }
        if (result.exitCode() == null) {
            return ValidationOutcome.notRun(
                    "The full build did not finish, so whether this change actually builds is unknown. "
                            + result.failureMessage(),
                    command, result.output());
        }
        if (result.exitCode() != 0) {
            return ValidationOutcome.failed(
                    "The full build failed: " + String.join(" ", command) + " exited with code "
                            + result.exitCode() + ". The commit was kept for diagnosis; see the build log.",
                    command, result.output());
        }
        return ValidationOutcome.passed(
                "The full build succeeded: " + String.join(" ", command) + " exited 0.",
                command, result.output());
    }
}
