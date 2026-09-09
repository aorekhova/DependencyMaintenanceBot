package com.tungsten.depbot.jenkins;

/**
 * Keeps only the tail of a Jenkins console log -- where a failure's own error text actually surfaces --
 * instead of embedding an unbounded log in a prompt or a report.
 */
public final class JenkinsConsoleLogExcerpt {

    private static final String TRUNCATION_MARKER = "...[truncated]\n";

    private JenkinsConsoleLogExcerpt() {
    }

    public static String truncate(String fullLog, int maxChars) {
        if (fullLog == null) {
            return null;
        }
        if (fullLog.length() <= maxChars) {
            return fullLog;
        }
        return TRUNCATION_MARKER + fullLog.substring(fullLog.length() - maxChars);
    }
}
