package com.tungsten.depbot.config;

import java.util.Map;

/**
 * The Mend credentials, read from the process environment.
 *
 * <p>These two variable names are the application's entire configuration interface.
 *
 * <p><strong>The {@link #toString()} override is a security control, not cosmetics.</strong>
 * A record's generated {@code toString} prints every component, so the default would render as
 * {@code EnvConfig[userKey=<real key>, projectToken=<real token>]} and leak both credentials
 * through any string concatenation, debug print, or assertion-failure message — bypassing the
 * console reporter and its redactor entirely.
 */
public record EnvConfig(String userKey, String projectToken) {

    public static final String MEND_USER_KEY = "MEND_USER_KEY";
    public static final String MEND_PROJECT_TOKEN = "MEND_PROJECT_TOKEN";

    /** Reads the credentials from the real process environment. */
    public static EnvConfig fromEnvironment() {
        return fromEnvironment(System.getenv());
    }

    /**
     * Reads the credentials from the supplied map.
     *
     * <p>Package-private so tests can inject values: {@code System.getenv()} cannot be mutated
     * reliably from within a JVM, and reading the real environment would make tests pass or fail
     * depending on the developer's machine.
     */
    static EnvConfig fromEnvironment(Map<String, String> environment) {
        return new EnvConfig(
                require(environment, MEND_USER_KEY),
                require(environment, MEND_PROJECT_TOKEN));
    }

    private static String require(Map<String, String> environment, String name) {
        String value = environment == null ? null : environment.get(name);
        if (value == null || value.isBlank()) {
            throw new ConfigurationException("Missing required environment variable: " + name);
        }
        // Windows `set VAR=value ` keeps trailing spaces and pasted tokens often carry a
        // newline; the stripped value is what gets sent to Mend.
        return value.strip();
    }

    @Override
    public String toString() {
        return "EnvConfig[userKey=***, projectToken=***]";
    }
}
