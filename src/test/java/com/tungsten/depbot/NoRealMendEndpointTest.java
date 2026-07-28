package com.tungsten.depbot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Turns two project rules into build-enforced facts rather than conventions a future
 * contributor might not know about.
 *
 * <p>Rule one: no automated test may reference the real Mend host. Rule two: no test may call
 * the no-argument {@code EnvConfig.fromEnvironment()}, which reads the developer's real
 * environment and would make results depend on the machine — and could put a real credential
 * into an assertion-failure message.
 *
 * <p>The forbidden strings are assembled at runtime so this file does not itself contain them.
 */
class NoRealMendEndpointTest {

    private static final String FORBIDDEN_HOST = "saas." + "whitesourcesoftware" + ".com";
    private static final String FORBIDDEN_VENDOR_HOST = "whitesourcesoftware" + ".com";
    private static final String FORBIDDEN_ENV_CALL = "fromEnvironment" + "()";

    private static final List<Path> TEST_ROOTS = List.of(
            Paths.get("src", "test", "java"),
            Paths.get("src", "test", "resources"));

    private static List<Path> testFiles() {
        List<Path> files = new ArrayList<>();
        for (Path root : TEST_ROOTS) {
            if (!Files.isDirectory(root)) {
                continue;
            }
            try (Stream<Path> walk = Files.walk(root)) {
                walk.filter(Files::isRegularFile).forEach(files::add);
            } catch (IOException e) {
                throw new UncheckedIOException("Could not scan " + root, e);
            }
        }
        return files;
    }

    private static String read(Path file) {
        try {
            return new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + file, e);
        }
    }

    /**
     * Removes block and Javadoc comments so that prose <em>describing</em> a forbidden call is
     * not mistaken for the call itself.
     *
     * <p>Only block comments are stripped. Line comments are left alone on purpose: a naive
     * strip from {@code //} to end of line would also truncate string literals such as
     * {@code "http://127.0.0.1"} and could hide a real offender.
     */
    private static String withoutBlockComments(String source) {
        return source.replaceAll("(?s)/\\*.*?\\*/", " ");
    }

    @Test
    @DisplayName("the scan actually finds test sources to check")
    void scannerSeesTestSources() {
        List<Path> files = testFiles();
        assertTrue(files.size() > 5,
                "expected to scan the test tree but found only " + files.size()
                        + " files; the guard would pass vacuously");
    }

    @Test
    @DisplayName("no test file references the real Mend host")
    void noTestReferencesTheRealMendHost() {
        List<String> offenders = new ArrayList<>();

        for (Path file : testFiles()) {
            if (file.getFileName().toString().equals("NoRealMendEndpointTest.java")) {
                continue;
            }
            String content = read(file);
            if (content.contains(FORBIDDEN_HOST) || content.contains(FORBIDDEN_VENDOR_HOST)) {
                offenders.add(file.toString());
            }
        }

        if (!offenders.isEmpty()) {
            fail("Automated tests must never contact the real Mend API. "
                    + "The real host appears in: " + offenders);
        }
    }

    @Test
    @DisplayName("no test calls the no-argument EnvConfig.fromEnvironment()")
    void noTestReadsTheRealEnvironment() {
        List<String> offenders = new ArrayList<>();

        for (Path file : testFiles()) {
            if (file.getFileName().toString().equals("NoRealMendEndpointTest.java")) {
                continue;
            }
            if (withoutBlockComments(read(file)).contains(FORBIDDEN_ENV_CALL)) {
                offenders.add(file.toString());
            }
        }

        if (!offenders.isEmpty()) {
            fail("Tests must inject a configuration map instead of reading the real "
                    + "environment. The no-argument call appears in: " + offenders);
        }
    }

    @Test
    @DisplayName("the comment-stripping still detects a genuine call")
    void detectionIsNotVacuous() {
        String describedInJavadoc = """
                /**
                 * This prose mentions fromEnvironment() but calls nothing.
                 */
                class Sample { }
                """;
        String actualCall = """
                class Sample {
                    void go() { EnvConfig.fromEnvironment(); }
                }
                """;

        assertTrue(withoutBlockComments(describedInJavadoc).contains(FORBIDDEN_ENV_CALL) == false,
                "prose in a block comment must not be treated as a call");
        assertTrue(withoutBlockComments(actualCall).contains(FORBIDDEN_ENV_CALL),
                "a genuine no-argument call must still be detected");
    }

    @Test
    @DisplayName("no test fixture contains a plausible real credential marker")
    void fixturesAreObviouslySynthetic() {
        Path fixtures = Paths.get("src", "test", "resources", "fixtures");
        assertTrue(Files.isDirectory(fixtures), "fixtures directory is missing; are the "
                + "fixtures excluded by .gitignore?");

        List<String> offenders = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(fixtures)) {
            walk.filter(Files::isRegularFile).forEach(file -> {
                String content = read(file);
                if (content.contains(FORBIDDEN_VENDOR_HOST)) {
                    offenders.add(file.toString());
                }
            });
        } catch (IOException e) {
            throw new UncheckedIOException("Could not scan fixtures", e);
        }

        if (!offenders.isEmpty()) {
            fail("Fixtures must be fully synthetic. Real vendor host found in: " + offenders);
        }
    }
}
