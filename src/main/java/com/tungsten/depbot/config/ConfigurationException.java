package com.tungsten.depbot.config;

/**
 * Signals that required configuration is missing or unusable.
 *
 * <p>A dedicated type rather than {@code IllegalStateException} so the CLI can map exactly this
 * condition to a configuration exit code, instead of accidentally catching an unrelated
 * {@code IllegalStateException} thrown from somewhere deep in the JDK.
 *
 * <p>Messages name the offending environment variable and never its value.
 */
public class ConfigurationException extends RuntimeException {

    public ConfigurationException(String message) {
        super(message);
    }
}
