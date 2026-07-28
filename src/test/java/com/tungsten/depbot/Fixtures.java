package com.tungsten.depbot;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/**
 * Loads synthetic test fixtures from the classpath.
 *
 * <p>Every fixture is hand-authored with obviously fake library names, fake CVE-style
 * identifiers, and fake tokens. No fixture is derived from a real Mend report.
 *
 * <p>Reading is explicitly UTF-8 so results do not depend on the platform default charset.
 */
public final class Fixtures {

    private Fixtures() {
    }

    public static String load(String fileName) {
        String path = "/fixtures/" + fileName;
        try (InputStream in = Fixtures.class.getResourceAsStream(path)) {
            if (in == null) {
                throw new IllegalStateException("Missing test fixture on the classpath: " + path
                        + " (is it excluded by .gitignore or absent from src/test/resources?)");
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read test fixture " + path, e);
        }
    }
}
