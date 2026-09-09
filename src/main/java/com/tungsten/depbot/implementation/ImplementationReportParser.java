package com.tungsten.depbot.implementation;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.claude.JsonAnswerExtractor;

import java.util.ArrayList;
import java.util.List;

/**
 * Turns the implementation call's final message into a validated {@link ImplementationReport}.
 *
 * <p>Uses the same extraction as the assessment phase -- the last complete JSON object in the answer,
 * preferring a fenced block -- so both roles may write like developers and end with the document that
 * commits to a conclusion.
 *
 * <p>Validation is by conclusion, and is stricter in one direction only: a report claiming
 * {@link ImplementationConclusion#COMPLETED} must say what it changed, and a report claiming the
 * assessment was contradicted must say how. Everything else is optional, because what a given
 * remediation legitimately involves is not something a schema can predict.
 */
public final class ImplementationReportParser {

    private final JsonMapper mapper = JsonMapper.builder()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    /**
     * @throws ImplementationParseException if no report could be found, it could not be bound, or it does
     *                                      not satisfy what its own conclusion requires
     */
    public ImplementationReport parse(String answerText) {
        if (answerText == null || answerText.isBlank()) {
            throw new ImplementationParseException(
                    "The implementation produced no answer text to read.", ImplementationParseException.Kind.MISSING_REPORT);
        }

        String json = JsonAnswerExtractor.lastJsonObject(answerText);
        if (json == null) {
            throw new ImplementationParseException(
                    "The implementation answer contains no complete JSON object, so there is no report "
                            + "saying what it did.", ImplementationParseException.Kind.MISSING_REPORT);
        }

        ImplementationReport report;
        try {
            report = mapper.readValue(json, ImplementationReport.class);
        } catch (JsonProcessingException e) {
            throw new ImplementationParseException(
                    "The implementation report could not be read: " + rootCauseMessage(e),
                    ImplementationParseException.Kind.MALFORMED_REPORT, e);
        }

        validate(report);
        return report;
    }

    private static void validate(ImplementationReport report) {
        List<String> problems = new ArrayList<>();

        if (!ImplementationReport.CURRENT_SCHEMA_VERSION.equals(report.schemaVersion())) {
            problems.add("schemaVersion is \"" + report.schemaVersion() + "\", but this application "
                    + "understands only \"" + ImplementationReport.CURRENT_SCHEMA_VERSION + "\"");
        }
        if (isBlank(report.coordinates())) {
            problems.add("coordinates is missing, so it is not clear which library was worked on");
        }
        if (isBlank(report.summary())) {
            problems.add("summary is missing, so the report does not say what happened");
        }
        if (isBlank(report.observedState())) {
            problems.add("observedState is missing, so the report does not say what was actually found on "
                    + "the branch -- which is the one thing that has to be established before changing it");
        }
        if (report.conclusion() == null) {
            problems.add("conclusion is missing");
        } else {
            switch (report.conclusion()) {
                case COMPLETED -> {
                    if (report.changesMade().isEmpty()) {
                        problems.add("changesMade is empty on a COMPLETED conclusion, so the report does "
                                + "not say what was actually done");
                    }
                }
                case STOPPED_ASSESSMENT_CONTRADICTED -> {
                    if (report.divergenceFromAssessment().isEmpty()) {
                        problems.add("divergenceFromAssessment is empty on a "
                                + "STOPPED_ASSESSMENT_CONTRADICTED conclusion, so the report does not say "
                                + "what contradicted the assessment");
                    }
                }
                case STOPPED_BLOCKED -> {
                    if (report.risks().isEmpty() && report.remainingWork().isEmpty()) {
                        problems.add("a STOPPED_BLOCKED conclusion carries neither risks nor remainingWork, "
                                + "so it does not say what stopped it");
                    }
                }
                case STOPPED_PLAN_DEVIATION_REQUIRED -> {
                    if (report.risks().isEmpty() && report.remainingWork().isEmpty()) {
                        problems.add("a STOPPED_PLAN_DEVIATION_REQUIRED conclusion carries neither risks nor "
                                + "remainingWork, so it does not say what was wrong with the approved plan");
                    }
                }
            }
        }

        if (!problems.isEmpty()) {
            throw new ImplementationParseException(
                    "The implementation report is not valid: " + String.join("; ", problems) + ".",
                    ImplementationParseException.Kind.REPORT_VALIDATION_FAILED);
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
