package com.tungsten.depbot.jenkins;

import com.tungsten.depbot.config.ConfigurationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JenkinsConfigTest {

    private static Map<String, String> completeEnvironment() {
        Map<String, String> environment = new HashMap<>();
        environment.put(JenkinsConfig.JENKINS_BASE_URL, "https://jenkins.example.invalid");
        environment.put(JenkinsConfig.JENKINS_USERNAME, "bot");
        environment.put(JenkinsConfig.JENKINS_API_TOKEN, "TOKEN-DO-NOT-LEAK");
        return environment;
    }

    @Test
    @DisplayName("a missing base URL is a configuration error")
    void missingBaseUrlIsAConfigurationError() {
        Map<String, String> environment = completeEnvironment();
        environment.remove(JenkinsConfig.JENKINS_BASE_URL);
        assertThrows(ConfigurationException.class, () -> JenkinsConfig.fromEnvironment(environment));
    }

    @Test
    @DisplayName("a missing username is a configuration error")
    void missingUsernameIsAConfigurationError() {
        Map<String, String> environment = completeEnvironment();
        environment.remove(JenkinsConfig.JENKINS_USERNAME);
        assertThrows(ConfigurationException.class, () -> JenkinsConfig.fromEnvironment(environment));
    }

    @Test
    @DisplayName("a missing API token is a configuration error")
    void missingApiTokenIsAConfigurationError() {
        Map<String, String> environment = completeEnvironment();
        environment.remove(JenkinsConfig.JENKINS_API_TOKEN);
        assertThrows(ConfigurationException.class, () -> JenkinsConfig.fromEnvironment(environment));
    }

    @Test
    @DisplayName("the job name defaults to WebApplicationDependencyValidation")
    void jobNameDefaults() {
        JenkinsConfig config = JenkinsConfig.fromEnvironment(completeEnvironment());
        assertEquals("WebApplicationDependencyValidation", config.jobName());
    }

    @Test
    @DisplayName("build timeout and poll interval default, and are overridable via environment")
    void timeoutAndPollIntervalDefaultAndOverride() {
        JenkinsConfig defaults = JenkinsConfig.fromEnvironment(completeEnvironment());
        assertEquals(Duration.ofSeconds(2700), defaults.buildTimeout());
        assertEquals(Duration.ofSeconds(15), defaults.pollInterval());

        Map<String, String> environment = completeEnvironment();
        environment.put(JenkinsConfig.JENKINS_BUILD_TIMEOUT_SECONDS, "60");
        environment.put(JenkinsConfig.JENKINS_POLL_INTERVAL_SECONDS, "5");
        JenkinsConfig overridden = JenkinsConfig.fromEnvironment(environment);
        assertEquals(Duration.ofSeconds(60), overridden.buildTimeout());
        assertEquals(Duration.ofSeconds(5), overridden.pollInterval());
    }

    @Test
    @DisplayName("toString never leaks the API token")
    void toStringNeverLeaksTheToken() {
        JenkinsConfig config = JenkinsConfig.fromEnvironment(completeEnvironment());
        assertFalse(config.toString().contains("TOKEN-DO-NOT-LEAK"));
        assertTrue(config.toString().contains("apiToken=***"));
    }
}
