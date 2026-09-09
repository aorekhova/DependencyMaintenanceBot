package com.tungsten.depbot.run;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RunPathsTest {

    private static final Path RUNS_ROOT = Path.of("reports", "runs");

    @Test
    @DisplayName("manifestPath sits directly under the run's own directory")
    void manifestPathIsUnderRunDirectory() {
        assertEquals(RUNS_ROOT.resolve("run1").resolve("run-manifest.json"),
                RunPaths.manifestPath(RUNS_ROOT, "run1"));
    }

    @Test
    @DisplayName("taskFilePath groups files by severity and joins groupId/artifactId with a double underscore")
    void taskFilePathGroupsBySeverity() {
        Path path = RunPaths.taskFilePath(RUNS_ROOT, "run1", "CRITICAL", "org.bouncycastle", "bcprov-jdk18on");

        assertEquals(RUNS_ROOT.resolve("run1").resolve("tasks").resolve("critical")
                        .resolve("org.bouncycastle__bcprov-jdk18on.md"),
                path);
    }

    @Test
    @DisplayName("taskFilePath sanitizes characters that are not safe in a filename")
    void taskFilePathSanitizesUnsafeCharacters() {
        Path path = RunPaths.taskFilePath(RUNS_ROOT, "run1", "high", "g:with/slash", "a?with*star");

        assertEquals("g_with_slash__a_with_star.md", path.getFileName().toString());
    }

    @Test
    @DisplayName("two different libraries in the same severity never collide even with similar names")
    void differentLibrariesProduceDifferentPaths() {
        Path a = RunPaths.taskFilePath(RUNS_ROOT, "run1", "critical", "com.foo", "commons-lang");
        Path b = RunPaths.taskFilePath(RUNS_ROOT, "run1", "critical", "org.bar", "commons-lang");

        assertEquals(false, a.equals(b));
    }
}
