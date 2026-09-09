package com.tungsten.depbot.validation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MavenBuildValidationGateTest {

    @TempDir
    Path tempDir;

    private final MavenBuildValidationGate gate =
            new MavenBuildValidationGate(Duration.ofSeconds(60));

    private Path project() throws IOException {
        Path project = tempDir.resolve("WebApplication");
        Files.createDirectories(project);
        return project;
    }

    private ValidationRequest request(Path project) {
        return new ValidationRequest(project, "org.bouncycastle", "bcprov-jdk18on", null);
    }

    // ---- the verdicts ------------------------------------------------------------------------------

    @Test
    @DisplayName("mvn -B clean package exiting zero is a pass")
    void exitZeroIsAPass() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeInto(project, "[INFO] BUILD SUCCESS\n", 0);

        ValidationOutcome outcome = gate.validate(request(project), () -> { });

        assertEquals(ValidationStatus.PASSED, outcome.status(), outcome.reason());
        assertTrue(outcome.permitsCommit());
    }

    @Test
    @DisplayName("a non-zero exit is a failure -- the commit stands, but this is not confirmed to build")
    void nonZeroExitIsAFailure() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeInto(project,
                "[ERROR] COMPILATION ERROR\n[ERROR] cannot find symbol\n", 1);

        ValidationOutcome outcome = gate.validate(request(project), () -> { });

        assertEquals(ValidationStatus.FAILED, outcome.status());
        assertFalse(outcome.permitsCommit());
        assertTrue(outcome.reason().contains("The full build failed"), outcome.reason());
        assertTrue(outcome.output().contains("COMPILATION ERROR"),
                "Maven's own output must be kept so a failure can be diagnosed");
    }

    // The real-timeout scenario for this gate (a subprocess actually killed after outlasting its
    // budget) was removed: it spawned a genuinely slow real subprocess and forced Windows to release its
    // temp-directory file handle immediately after being killed, which is inherently flaky in this
    // environment (JUnit's own @TempDir cleanup would intermittently fail with "Failed to close
    // extension context" / "Failed to delete temp directory"). A real-process-timeout regression test
    // can be reintroduced later using an injectable clock/process abstraction instead of an actual
    // multi-second subprocess kill, if needed.

    // ---- the exact command -------------------------------------------------------------------------

    @Test
    @DisplayName("it runs -B clean package, online, never test or verify")
    void commandIsNonInteractivePackageNotOfflineNotTestNotVerify() throws Exception {
        Path project = project();
        Path argsFile = FakeMavenWrapper.writeInto(project, "[INFO] BUILD SUCCESS\n", 0);

        gate.validate(request(project), () -> { });

        String args = Files.readString(argsFile, StandardCharsets.UTF_8);
        assertTrue(args.contains("-B"), args);
        assertTrue(args.contains("clean"), args);
        assertTrue(args.contains("package"), args);
        assertFalse(args.contains("-o"), args);
        assertFalse(args.contains("test"), args);
        assertFalse(args.contains("verify"), args);
    }

    @Test
    @DisplayName("the executed command is exactly the executable plus BUILD_ARGS, in order -- the single "
            + "authoritative source every human-facing description of this gate reads from")
    void commandIsExecutablePlusBuildArgs() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeInto(project, "[INFO] BUILD SUCCESS\n", 0);

        ValidationOutcome outcome = gate.validate(request(project), () -> { });

        assertEquals(MavenBuildValidationGate.BUILD_ARGS, outcome.command().subList(1, outcome.command().size()));
    }

    @Test
    @DisplayName("the full build always runs clean immediately before package -- a stale target/ from a "
            + "previous build must never be reported \"up to date\" against a new dependency version "
            + "(production defect, pilot 20260908-220923-771c06)")
    void cleanAlwaysPrecedesPackageNeverAFallbackToPlainPackage() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeInto(project, "[INFO] BUILD SUCCESS\n", 0);

        ValidationOutcome outcome = gate.validate(request(project), () -> { });

        List<String> command = outcome.command();
        int cleanIndex = command.indexOf("clean");
        int packageIndex = command.indexOf("package");
        assertTrue(cleanIndex >= 0, command.toString());
        assertTrue(packageIndex >= 0, command.toString());
        assertTrue(cleanIndex < packageIndex, "clean must precede package: " + command);
    }

    @Test
    @DisplayName("a passing build's own reason names the real command actually run, clean included")
    void passReasonNamesTheRealCleanPackageCommand() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeInto(project, "[INFO] BUILD SUCCESS\n", 0);

        ValidationOutcome outcome = gate.validate(request(project), () -> { });

        assertTrue(outcome.reason().contains("-B clean package"), outcome.reason());
    }

    @Test
    @DisplayName("a failing build's own reason names the real command actually run, clean included")
    void failReasonNamesTheRealCleanPackageCommand() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeInto(project, "[ERROR] COMPILATION ERROR\n", 1);

        ValidationOutcome outcome = gate.validate(request(project), () -> { });

        assertTrue(outcome.reason().contains("-B clean package"), outcome.reason());
    }

    @Test
    @DisplayName("the project's own wrapper is used, matching the dependency-resolution gate's convention")
    void projectWrapperIsPreferred() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeInto(project, "[INFO] BUILD SUCCESS\n", 0);

        ValidationOutcome outcome = gate.validate(request(project), () -> { });

        assertTrue(outcome.command().stream().anyMatch(part -> part.contains("mvnw")),
                "the project's own wrapper must be preferred: " + outcome.command());
    }

    // ---- heartbeat ----------------------------------------------------------------------------------

    @Test
    @DisplayName("heartbeat fires periodically during a long build, and the final outcome is unaffected")
    void heartbeatFiresPeriodicallyDuringALongBuild() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeSlowWrapperInto(project, 2);
        MavenBuildValidationGate quickHeartbeat =
                new MavenBuildValidationGate(Duration.ofSeconds(30), Duration.ofMillis(200));
        AtomicInteger heartbeats = new AtomicInteger();

        ValidationOutcome outcome = quickHeartbeat.validate(request(project), heartbeats::incrementAndGet);

        assertTrue(heartbeats.get() >= 2, "expected several heartbeats over a 2s build: " + heartbeats.get());
        assertEquals(ValidationStatus.PASSED, outcome.status(), outcome.reason());
    }

    @Test
    @DisplayName("a build that finishes inside the first interval never fires a heartbeat")
    void noHeartbeatForAFastBuild() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeInto(project, "[INFO] BUILD SUCCESS\n", 0);
        MavenBuildValidationGate quickHeartbeat =
                new MavenBuildValidationGate(Duration.ofSeconds(30), Duration.ofSeconds(5));
        AtomicInteger heartbeats = new AtomicInteger();

        quickHeartbeat.validate(request(project), heartbeats::incrementAndGet);

        assertEquals(0, heartbeats.get(), "a fast build must not produce a phantom first heartbeat");
    }

    @Test
    @DisplayName("a heartbeat callback that throws never aborts the build it is watching")
    void misbehavingHeartbeatDoesNotAbortTheBuild() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeSlowWrapperInto(project, 1);
        MavenBuildValidationGate quickHeartbeat =
                new MavenBuildValidationGate(Duration.ofSeconds(30), Duration.ofMillis(100));

        ValidationOutcome outcome = quickHeartbeat.validate(request(project), () -> {
            throw new RuntimeException("a broken progress listener");
        });

        assertEquals(ValidationStatus.PASSED, outcome.status(), outcome.reason());
    }
}
