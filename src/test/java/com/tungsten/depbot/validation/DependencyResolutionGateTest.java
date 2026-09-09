package com.tungsten.depbot.validation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DependencyResolutionGateTest {

    private static final String COORDINATES_GROUP = "org.bouncycastle";
    private static final String COORDINATES_ARTIFACT = "bcprov-jdk18on";

    @TempDir
    Path tempDir;

    private final DependencyResolutionGate gate = new DependencyResolutionGate(Duration.ofSeconds(60));

    private Path project() throws IOException {
        Path project = tempDir.resolve("WebApplication");
        Files.createDirectories(project);
        return project;
    }

    private ValidationRequest request(Path project, String vulnerableVersion) {
        return new ValidationRequest(project, COORDINATES_GROUP, COORDINATES_ARTIFACT, vulnerableVersion);
    }

    private static String treeShowing(String version) {
        return """
                [INFO] --- dependency:3.6.0:tree (default-cli) @ webapp ---
                [INFO] com.example:webapp:war:9.2.0-SNAPSHOT
                [INFO] \\- org.bouncycastle:bcprov-jdk18on:jar:%s:compile
                [INFO] BUILD SUCCESS
                """.formatted(version);
    }

    // ---- the verdicts ----------------------------------------------------------------------------

    @Test
    @DisplayName("a resolving model with the vulnerable version gone is a pass")
    void vulnerableVersionGoneIsAPass() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeInto(project, treeShowing("1.85"), 0);

        ValidationOutcome outcome = gate.validate(request(project, "1.84"));

        assertEquals(ValidationStatus.PASSED, outcome.status(), outcome.reason());
        assertTrue(outcome.permitsCommit());
        assertTrue(outcome.reason().contains("1.85"), outcome.reason());
    }

    // ---- resolvedVersion: a structured fact, not something read back out of the prose reason -------

    @Test
    @DisplayName("a pass with exactly one resolved version records it structurally")
    void passRecordsTheSingleResolvedVersionStructurally() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeInto(project, treeShowing("1.85"), 0);

        ValidationOutcome outcome = gate.validate(request(project, "1.84"));

        assertEquals(ValidationStatus.PASSED, outcome.status());
        assertEquals("1.85", outcome.resolvedVersion());
    }

    @Test
    @DisplayName("a pass where the tree resolves to more than one version records no single resolved "
            + "version, rather than guessing which one is authoritative")
    void passWithAmbiguousVersionsRecordsNoSingleResolvedVersion() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeInto(project, """
                [INFO] +- org.bouncycastle:bcprov-jdk18on:jar:1.85:compile
                [INFO] \\- org.bouncycastle:bcprov-jdk18on:jar:1.86:provided
                [INFO] BUILD SUCCESS
                """, 0);

        ValidationOutcome outcome = gate.validate(request(project, "1.84"));

        assertEquals(ValidationStatus.PASSED, outcome.status(), outcome.reason());
        assertNull(outcome.resolvedVersion(),
                "two different modules resolving two different versions is not a single answer to guess from");
    }

    @Test
    @DisplayName("the vulnerable version still resolving is a failure, whatever the report claimed")
    void vulnerableVersionStillResolvingIsAFailure() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeInto(project, treeShowing("1.84"), 0);

        ValidationOutcome outcome = gate.validate(request(project, "1.84"));

        assertEquals(ValidationStatus.FAILED, outcome.status());
        assertFalse(outcome.permitsCommit());
        assertTrue(outcome.reason().contains("still resolves to 1.84"), outcome.reason());
        assertTrue(outcome.reason().contains("did not take effect"), outcome.reason());
    }

    @Test
    @DisplayName("a build model that no longer resolves is a failure -- this is the broken-POM case")
    void nonZeroExitIsAFailure() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeInto(project,
                "[ERROR] Non-resolvable import POM: com.example:missing-bom:pom:9.9\n", 1);

        ValidationOutcome outcome = gate.validate(request(project, "1.84"));

        assertEquals(ValidationStatus.FAILED, outcome.status());
        assertTrue(outcome.reason().contains("no longer resolves"), outcome.reason());
        assertTrue(outcome.output().contains("Non-resolvable import POM"),
                "Maven's own output has to be kept, or a refusal cannot be diagnosed");
    }

    @Test
    @DisplayName("an artifact that no longer resolves at all is a pass, since the vulnerable version is gone")
    void artifactGoneEntirelyIsAPass() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeInto(project, "[INFO] com.example:webapp:war:9.2.0\n[INFO] BUILD SUCCESS\n", 0);

        ValidationOutcome outcome = gate.validate(request(project, "1.84"));

        assertEquals(ValidationStatus.PASSED, outcome.status(), outcome.reason());
        assertTrue(outcome.reason().contains("no longer resolves at all"), outcome.reason());
        assertNull(outcome.resolvedVersion(),
                "gone entirely is not a version to report, so this must not be invented either");
    }

    @Test
    @DisplayName("with no vulnerable version established, only the model resolving is checked")
    void withoutAVulnerableVersionOnlyResolutionIsChecked() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeInto(project, treeShowing("1.84"), 0);

        ValidationOutcome outcome = gate.validate(request(project, null));

        assertEquals(ValidationStatus.PASSED, outcome.status(), outcome.reason());
        assertTrue(outcome.reason().contains("nothing further could be checked"), outcome.reason());
    }

    // The real-timeout scenario for this gate (a subprocess actually killed after outlasting its
    // budget) was removed: it spawned a genuinely slow real subprocess and forced Windows to release its
    // temp-directory file handle immediately after being killed, which is inherently flaky in this
    // environment (JUnit's own @TempDir cleanup would intermittently fail with "Failed to close
    // extension context" / "Failed to delete temp directory"). A real-process-timeout regression test
    // can be reintroduced later using an injectable clock/process abstraction instead of an actual
    // multi-second subprocess kill, if needed.

    // ---- what it actually runs ---------------------------------------------------------------------

    @Test
    @DisplayName("it runs offline, non-interactive dependency:tree filtered to the one artifact")
    void runsOfflineNonInteractiveDependencyTree() throws Exception {
        Path project = project();
        Path argsFile = FakeMavenWrapper.writeInto(project, treeShowing("1.85"), 0);

        ValidationOutcome outcome = gate.validate(request(project, "1.84"));

        String args = Files.readString(argsFile, StandardCharsets.UTF_8);
        assertTrue(args.contains("-o"), args);
        assertTrue(args.contains("-B"), args);
        assertTrue(args.contains("dependency:tree"), args);
        assertTrue(args.contains("-Dincludes=org.bouncycastle:bcprov-jdk18on"), args);
        assertFalse(args.contains("compile"), args);
        assertFalse(args.contains("test"), args);
        assertFalse(args.contains("install"), args);
        assertTrue(outcome.command().stream().anyMatch(part -> part.contains("mvnw")),
                "the project's own wrapper must be preferred: " + outcome.command());
    }

    @Test
    @DisplayName("the project's wrapper is preferred over whatever mvn is on PATH")
    void projectWrapperIsPreferred() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeInto(project, treeShowing("1.85"), 0);

        assertTrue(MavenInvocation.executableFor(project).contains("mvnw"));
    }

    @Test
    @DisplayName("a project with no wrapper falls back to mvn on PATH")
    void withoutAWrapperMvnIsUsed() throws Exception {
        assertTrue(MavenInvocation.executableFor(project()).startsWith("mvn"));
    }

    // ---- version parsing, which is where a false verdict would come from ----------------------------

    @Test
    @DisplayName("the version is taken from the coordinate, not searched for as a bare string")
    void versionIsTakenFromTheCoordinate() {
        Set<String> versions = DependencyResolutionGate.resolvedVersionsOf(
                treeShowing("1.85"), COORDINATES_GROUP, COORDINATES_ARTIFACT);

        assertEquals(Set.of("1.85"), versions);
    }

    @Test
    @DisplayName("1.840 is never mistaken for 1.84, which would be a false 'still vulnerable'")
    void similarVersionsAreNotConfused() {
        Set<String> versions = DependencyResolutionGate.resolvedVersionsOf(
                treeShowing("1.840"), COORDINATES_GROUP, COORDINATES_ARTIFACT);

        assertEquals(Set.of("1.840"), versions);
        assertFalse(versions.contains("1.84"));
    }

    @Test
    @DisplayName("another artifact at the vulnerable version is not attributed to this one")
    void otherArtifactsAreNotAttributed() {
        String tree = """
                [INFO] +- org.other:something:jar:1.84:compile
                [INFO] \\- org.bouncycastle:bcprov-jdk18on:jar:1.85:compile
                """;

        assertEquals(Set.of("1.85"), DependencyResolutionGate.resolvedVersionsOf(
                tree, COORDINATES_GROUP, COORDINATES_ARTIFACT));
    }

    @Test
    @DisplayName("a groupId that merely ends with the one being looked for does not match")
    void partialGroupIdDoesNotMatch() {
        String tree = "[INFO] \\- xorg.bouncycastle:bcprov-jdk18on:jar:1.84:compile\n";

        assertTrue(DependencyResolutionGate.resolvedVersionsOf(
                tree, COORDINATES_GROUP, COORDINATES_ARTIFACT).isEmpty());
    }

    @Test
    @DisplayName("a classifier between packaging and version does not shift the version")
    void classifierDoesNotShiftTheVersion() {
        String tree = "[INFO] \\- org.bouncycastle:bcprov-jdk18on:jar:jdk18on:1.85:compile\n";

        assertEquals(Set.of("1.85"), DependencyResolutionGate.resolvedVersionsOf(
                tree, COORDINATES_GROUP, COORDINATES_ARTIFACT));
    }

    @Test
    @DisplayName("a coordinate with no scope still yields its version")
    void coordinateWithoutScopeStillYieldsAVersion() {
        String tree = "[INFO] org.bouncycastle:bcprov-jdk18on:jar:1.85\n";

        assertEquals(Set.of("1.85"), DependencyResolutionGate.resolvedVersionsOf(
                tree, COORDINATES_GROUP, COORDINATES_ARTIFACT));
    }

    @Test
    @DisplayName("every version across a multi-module tree is collected, not just the first")
    void everyModulesVersionIsCollected() {
        String tree = """
                [INFO] +- org.bouncycastle:bcprov-jdk18on:jar:1.85:compile
                [INFO] --- module two ---
                [INFO] \\- org.bouncycastle:bcprov-jdk18on:jar:1.84:provided
                """;

        Set<String> versions = DependencyResolutionGate.resolvedVersionsOf(
                tree, COORDINATES_GROUP, COORDINATES_ARTIFACT);

        assertEquals(Set.of("1.85", "1.84"), versions);
    }

    @Test
    @DisplayName("one module left on the vulnerable version fails the whole gate")
    void oneModuleLeftBehindFailsTheGate() throws Exception {
        Path project = project();
        FakeMavenWrapper.writeInto(project, """
                [INFO] +- org.bouncycastle:bcprov-jdk18on:jar:1.85:compile
                [INFO] \\- org.bouncycastle:bcprov-jdk18on:jar:1.84:provided
                [INFO] BUILD SUCCESS
                """, 0);

        ValidationOutcome outcome = gate.validate(request(project, "1.84"));

        assertEquals(ValidationStatus.FAILED, outcome.status());
        assertTrue(outcome.reason().contains("still resolves to 1.84"), outcome.reason());
    }
}
