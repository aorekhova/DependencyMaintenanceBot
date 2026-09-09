package com.tungsten.depbot.humanreview;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.claude.JsonAnswerExtractor;

import java.util.ArrayList;
import java.util.List;

/**
 * Turns the Human Review Engineer's final message into a validated {@link HumanReviewReport}.
 *
 * <p>Same extraction approach as the other two roles' parsers -- the last complete JSON object in the
 * answer. The five questions with a required, single-sentence-or-more answer must all be non-blank;
 * {@code relatedDependenciesToConsider} may legitimately be empty (not every finding has related
 * dependencies worth naming).
 */
public final class HumanReviewReportParser {

    private final JsonMapper mapper = JsonMapper.builder()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    /**
     * @throws HumanReviewParseException if no report could be found, it could not be bound, or it does
     *                                   not answer the fixed questions it must
     */
    public HumanReviewReport parse(String answerText) {
        if (answerText == null || answerText.isBlank()) {
            throw new HumanReviewParseException("The human review produced no answer text to read.");
        }

        String json = JsonAnswerExtractor.lastJsonObject(answerText);
        if (json == null) {
            throw new HumanReviewParseException(
                    "The human review answer contains no complete JSON object, so there is no report to read.");
        }

        HumanReviewReport report;
        try {
            report = mapper.readValue(json, HumanReviewReport.class);
        } catch (JsonProcessingException e) {
            throw new HumanReviewParseException(
                    "The human review report could not be read: " + rootCauseMessage(e), e);
        }

        validate(report);
        return report;
    }

    private static void validate(HumanReviewReport report) {
        List<String> problems = new ArrayList<>();

        if (!HumanReviewReport.CURRENT_SCHEMA_VERSION.equals(report.schemaVersion())) {
            problems.add("schemaVersion is \"" + report.schemaVersion() + "\", but this application "
                    + "understands only \"" + HumanReviewReport.CURRENT_SCHEMA_VERSION + "\"");
        }
        if (isBlank(report.coordinates())) {
            problems.add("coordinates is missing, so it is not clear which finding this report is about");
        }
        if (isBlank(report.vulnerabilitySummary())) {
            problems.add("vulnerabilitySummary is missing -- the report does not say what is vulnerable");
        }
        if (isBlank(report.whyVulnerable())) {
            problems.add("whyVulnerable is missing -- the report does not say why");
        }
        if (isBlank(report.dependencyOrigin())) {
            problems.add("dependencyOrigin is missing -- the report does not say where the dependency came from");
        }
        if (isBlank(report.recommendedChange())) {
            problems.add("recommendedChange is missing -- the report does not say what needs to change");
        }
        if (isBlank(report.validationApproach())) {
            problems.add("validationApproach is missing -- the report does not say how to validate a fix");
        }

        if (!problems.isEmpty()) {
            throw new HumanReviewParseException(
                    "The human review report is not valid: " + String.join("; ", problems) + ".");
        }
    }

    private static String rootCauseMessage(Throwable throwable) {
        Throwable cause = throwable;
        while (cause.getCause() != null && cause.getCause() != cause) {
            cause = cause.getCause();
        }
        String message = cause.getMessage();
        return (message == null || message.isBlank()) ? cause.getClass().getSimpleName() : message;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
