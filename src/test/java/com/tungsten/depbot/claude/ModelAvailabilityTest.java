package com.tungsten.depbot.claude;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ModelAvailabilityTest {

    @Test
    @DisplayName("a model-permission rejection on stderr is recognised")
    void permissionRejectionIsRecognised() {
        assertTrue(ModelAvailability.looksUnavailable(
                "", "Error: your account does not have access to the requested model"));
    }

    @Test
    @DisplayName("an unknown-model rejection in the JSON output is recognised")
    void unknownModelInJsonIsRecognised() {
        assertTrue(ModelAvailability.looksUnavailable(
                "{\"error\":{\"type\":\"model_not_found\"}}", ""));
    }

    @Test
    @DisplayName("recognition is case-insensitive")
    void recognitionIsCaseInsensitive() {
        assertTrue(ModelAvailability.looksUnavailable("", "INVALID MODEL: opus"));
    }

    @Test
    @DisplayName("an ordinary failure is not mistaken for a model problem")
    void ordinaryFailureIsNotMistaken() {
        assertFalse(ModelAvailability.looksUnavailable(
                "{\"result\":\"could not edit pom.xml\"}", "compilation failed"));
    }

    @Test
    @DisplayName("null streams are handled without throwing")
    void nullStreamsAreSafe() {
        assertFalse(ModelAvailability.looksUnavailable(null, null));
    }

    @Test
    @DisplayName("the message names the model and states that nothing was substituted")
    void messageNamesModelAndRefusesSubstitution() {
        String message = ModelAvailability.unavailableMessage("opus");

        assertTrue(message.contains("opus"));
        assertTrue(message.contains("No weaker model was substituted"), message);
        assertTrue(message.contains(ClaudeConfig.CLAUDE_MODEL), message);
    }
}
