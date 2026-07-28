package com.tungsten.depbot.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every test injects a map. The no-argument {@code fromEnvironment()} is deliberately never
 * called here: it would read the developer's real environment, making results machine-dependent
 * and risking a real credential appearing in an assertion-failure message. That rule is enforced
 * by {@code NoRealMendEndpointTest}.
 */
class EnvConfigTest {

    private static final String USER_KEY = "USERKEY-DO-NOT-LEAK-9f3a";
    private static final String TOKEN = "TOKEN-DO-NOT-LEAK-7b1c";

    private static Map<String, String> env(String userKey, String projectToken) {
        Map<String, String> map = new HashMap<>();
        if (userKey != null) {
            map.put(EnvConfig.MEND_USER_KEY, userKey);
        }
        if (projectToken != null) {
            map.put(EnvConfig.MEND_PROJECT_TOKEN, projectToken);
        }
        return map;
    }

    @Test
    @DisplayName("both variables present yields a populated config")
    void bothPresent() {
        EnvConfig config = EnvConfig.fromEnvironment(env(USER_KEY, TOKEN));
        assertEquals(USER_KEY, config.userKey());
        assertEquals(TOKEN, config.projectToken());
    }

    @Test
    @DisplayName("missing MEND_USER_KEY is rejected by name")
    void missingUserKey() {
        ConfigurationException thrown = assertThrows(ConfigurationException.class,
                () -> EnvConfig.fromEnvironment(env(null, TOKEN)));
        assertTrue(thrown.getMessage().contains(EnvConfig.MEND_USER_KEY));
    }

    @Test
    @DisplayName("missing MEND_PROJECT_TOKEN is rejected by name")
    void missingProjectToken() {
        ConfigurationException thrown = assertThrows(ConfigurationException.class,
                () -> EnvConfig.fromEnvironment(env(USER_KEY, null)));
        assertTrue(thrown.getMessage().contains(EnvConfig.MEND_PROJECT_TOKEN));
    }

    @Test
    @DisplayName("an empty value is treated as missing")
    void emptyValueIsMissing() {
        assertThrows(ConfigurationException.class,
                () -> EnvConfig.fromEnvironment(env("", TOKEN)));
    }

    @Test
    @DisplayName("a whitespace-only value is treated as missing")
    void whitespaceOnlyValueIsMissing() {
        assertThrows(ConfigurationException.class,
                () -> EnvConfig.fromEnvironment(env(USER_KEY, "   ")));
    }

    @Test
    @DisplayName("a null environment map is treated as missing configuration")
    void nullEnvironmentIsMissing() {
        assertThrows(ConfigurationException.class, () -> EnvConfig.fromEnvironment(null));
    }

    @Test
    @DisplayName("surrounding whitespace is stripped and the stripped value is stored")
    void valuesAreStripped() {
        EnvConfig config = EnvConfig.fromEnvironment(
                env("  " + USER_KEY + "  ", TOKEN + "\n"));
        assertEquals(USER_KEY, config.userKey());
        assertEquals(TOKEN, config.projectToken());
    }

    @Test
    @DisplayName("the error message names the variable but never its value")
    void errorMessageNamesVariableNotValue() {
        Map<String, String> environment = env("   ", TOKEN);
        ConfigurationException thrown = assertThrows(ConfigurationException.class,
                () -> EnvConfig.fromEnvironment(environment));

        assertTrue(thrown.getMessage().contains(EnvConfig.MEND_USER_KEY));
        assertFalse(thrown.getMessage().contains(TOKEN));
    }

    @Test
    @DisplayName("toString masks both credentials")
    void toStringMasksBothCredentials() {
        String text = EnvConfig.fromEnvironment(env(USER_KEY, TOKEN)).toString();

        assertFalse(text.contains(USER_KEY), "userKey leaked via toString: " + text);
        assertFalse(text.contains(TOKEN), "projectToken leaked via toString: " + text);
        assertEquals("EnvConfig[userKey=***, projectToken=***]", text);
    }

    @Test
    @DisplayName("string concatenation of the config cannot leak credentials")
    void concatenationDoesNotLeak() {
        EnvConfig config = EnvConfig.fromEnvironment(env(USER_KEY, TOKEN));
        String message = "loaded " + config;

        assertFalse(message.contains(USER_KEY));
        assertFalse(message.contains(TOKEN));
    }
}
