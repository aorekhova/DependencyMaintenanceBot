package com.tungsten.depbot.implementation;

import com.tungsten.depbot.assessment.Assessments;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ImplementationReportParserTest {

    private final ImplementationReportParser parser = new ImplementationReportParser();

    @Test
    @DisplayName("a completed report binds every field")
    void completedReportBinds() {
        ImplementationReport report = parser.parse(Implementations.completedJson());

        assertEquals(ImplementationConclusion.COMPLETED, report.conclusion());
        assertEquals("org.bouncycastle:bcprov-jdk18on", report.coordinates());
        assertTrue(report.observedState().contains("1.84"), report.observedState());
        assertEquals(2, report.changesMade().size());
        assertEquals(List.of("dependency:tree resolves 1.85 in every module"), report.validationPerformed());
        assertTrue(report.workCompleted());
    }

    @Test
    @DisplayName("a report found inside prose and a fenced block is still read")
    void reportInsideProseIsFound() {
        ImplementationReport report =
                parser.parse(Assessments.answerContaining(Implementations.completedJson()));

        assertEquals(ImplementationConclusion.COMPLETED, report.conclusion());
    }

    @Test
    @DisplayName("a safe stop on contradicted evidence is a valid report, and does not count as completed")
    void contradictedStopIsValidButNotCompleted() {
        ImplementationReport report = parser.parse(Implementations.contradictedJson());

        assertEquals(ImplementationConclusion.STOPPED_ASSESSMENT_CONTRADICTED, report.conclusion());
        assertFalse(report.workCompleted());
        assertEquals(2, report.divergenceFromAssessment().size());
    }

    @Test
    @DisplayName("a blocked stop is a valid report and does not count as completed")
    void blockedStopIsValidButNotCompleted() {
        ImplementationReport report = parser.parse(Implementations.blockedJson());

        assertEquals(ImplementationConclusion.STOPPED_BLOCKED, report.conclusion());
        assertFalse(report.workCompleted());
    }

    @ParameterizedTest
    @ValueSource(strings = {"completed", "  COMPLETED  ", "Completed"})
    @DisplayName("the conclusion is read tolerantly of case and spacing")
    void conclusionIsReadTolerantly(String raw) {
        assertEquals(ImplementationConclusion.COMPLETED, ImplementationConclusion.from(raw));
    }

    @Test
    @DisplayName("an unrecognised conclusion is rejected, never mapped to a default")
    void unrecognisedConclusionIsRejected() {
        ImplementationParseException thrown = assertThrows(ImplementationParseException.class,
                () -> parser.parse(Implementations.completedJson().replace("COMPLETED", "MOSTLY_FINE")));

        assertTrue(thrown.getMessage().contains("MOSTLY_FINE"), thrown.getMessage());
    }

    @Test
    @DisplayName("observedState is required whatever the conclusion -- it is the safe-stop contract")
    void observedStateIsAlwaysRequired() {
        String withoutObservedState = Implementations.completedJson()
                .replaceAll("\"observedState\":[^\n]*\n", "");

        ImplementationParseException thrown = assertThrows(ImplementationParseException.class,
                () -> parser.parse(withoutObservedState));

        assertTrue(thrown.getMessage().contains("observedState"), thrown.getMessage());
    }

    @Test
    @DisplayName("a completed report that lists no changes is rejected")
    void completedWithoutChangesIsRejected() {
        String noChanges = """
                {"schemaVersion":"1.0","coordinates":"g:a","conclusion":"COMPLETED",
                 "summary":"done","observedState":"as assessed","changesMade":[]}
                """;

        ImplementationParseException thrown =
                assertThrows(ImplementationParseException.class, () -> parser.parse(noChanges));

        assertTrue(thrown.getMessage().contains("changesMade"), thrown.getMessage());
    }

    @Test
    @DisplayName("a contradiction stop that does not say what diverged is rejected")
    void contradictionWithoutDivergenceIsRejected() {
        String silent = """
                {"schemaVersion":"1.0","coordinates":"g:a","conclusion":"STOPPED_ASSESSMENT_CONTRADICTED",
                 "summary":"stopped","observedState":"not what was expected"}
                """;

        ImplementationParseException thrown =
                assertThrows(ImplementationParseException.class, () -> parser.parse(silent));

        assertTrue(thrown.getMessage().contains("divergence"), thrown.getMessage());
    }

    @Test
    @DisplayName("a blocked stop that does not say what stopped it is rejected")
    void blockedWithoutAReasonIsRejected() {
        String silent = """
                {"schemaVersion":"1.0","coordinates":"g:a","conclusion":"STOPPED_BLOCKED",
                 "summary":"stopped","observedState":"as assessed"}
                """;

        assertThrows(ImplementationParseException.class, () -> parser.parse(silent));
    }

    @Test
    @DisplayName("a divergence recorded on a completed report is allowed -- being partly wrong is fine")
    void divergenceOnACompletedReportIsAllowed() {
        String withDivergence = Implementations.completedJson().replace(
                "\"divergenceFromAssessment\": []",
                "\"divergenceFromAssessment\": [\"the property lives in the parent pom, not the root\"]");

        ImplementationReport report = parser.parse(withDivergence);

        assertEquals(ImplementationConclusion.COMPLETED, report.conclusion());
        assertEquals(1, report.divergenceFromAssessment().size());
    }

    @Test
    @DisplayName("an unknown schema version is rejected")
    void unknownSchemaVersionIsRejected() {
        assertThrows(ImplementationParseException.class,
                () -> parser.parse(Implementations.completedJson().replace("\"1.0\"", "\"2.0\"")));
    }

    @Test
    @DisplayName("an unknown extra field is tolerated")
    void unknownFieldsAreTolerated() {
        assertEquals(ImplementationConclusion.COMPLETED,
                parser.parse(Implementations.completedJson("\"tokensUsed\": 1234")).conclusion());
    }

    @Test
    @DisplayName("an answer with no report is rejected without quoting the answer back")
    void answerWithoutAReportIsRejected() {
        String prose = "I changed the pom. The token in .env.local was hunter2, by the way.";

        ImplementationParseException thrown =
                assertThrows(ImplementationParseException.class, () -> parser.parse(prose));

        assertFalse(thrown.getMessage().contains("hunter2"), thrown.getMessage());
    }

    @Test
    @DisplayName("an empty or absent answer is rejected")
    void emptyAnswerIsRejected() {
        assertThrows(ImplementationParseException.class, () -> parser.parse(""));
        assertThrows(ImplementationParseException.class, () -> parser.parse(null));
    }
}
