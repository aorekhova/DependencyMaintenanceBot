package com.tungsten.depbot.mend;

import com.tungsten.depbot.Fixtures;
import com.tungsten.depbot.mend.model.VulnerabilityReport;
import com.tungsten.depbot.report.SeverityCounts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MendResponseParserTest {

    private final MendResponseParser parser = new MendResponseParser();

    // ---------- success paths ----------

    @Test
    @DisplayName("a mixed-severity report parses and counts correctly")
    void mixedSeverities() {
        VulnerabilityReport report = parser.parse(Fixtures.load("success-mixed-severities.json"));
        SeverityCounts counts = SeverityCounts.from(report.vulnerabilities());

        assertEquals(6, counts.total());
        assertEquals(1, counts.criticalCount());
        assertEquals(2, counts.highCount());
        assertEquals(1, counts.mediumCount());
        assertEquals(1, counts.lowCount());
        assertEquals(1, counts.otherCount());
    }

    @Test
    @DisplayName("an empty vulnerabilities array is a valid report with total zero")
    void emptyArrayIsValid() {
        VulnerabilityReport report = parser.parse(Fixtures.load("success-empty.json"));
        assertTrue(report.vulnerabilities().isEmpty());
        assertEquals(0, SeverityCounts.from(report.vulnerabilities()).total());
    }

    @Test
    @DisplayName("unknown fields in a realistic payload are ignored")
    void extraFieldsAreIgnored() {
        VulnerabilityReport report = parser.parse(Fixtures.load("success-extra-fields.json"));
        SeverityCounts counts = SeverityCounts.from(report.vulnerabilities());

        assertEquals(2, counts.total());
        assertEquals(1, counts.highCount());
        assertEquals(1, counts.lowCount());
    }

    // ---------- in-band Mend error envelope ----------

    @Test
    @DisplayName("an errorCode payload becomes a MendApiException carrying the code")
    void inBandErrorBecomesApiException() {
        MendApiException thrown = assertThrows(MendApiException.class,
                () -> parser.parse(Fixtures.load("error-1004.json")));

        assertEquals(1004, thrown.errorCode());
        assertEquals("Invalid project token", thrown.getMessage());
    }

    @Test
    @DisplayName("a non-integer errorCode is malformed, not error code zero")
    void nonIntegerErrorCodeIsMalformed() {
        assertThrows(MalformedResponseException.class,
                () -> parser.parse(Fixtures.load("error-non-integer-code.json")));
    }

    @Test
    @DisplayName("a null errorCode is malformed")
    void nullErrorCodeIsMalformed() {
        assertThrows(MalformedResponseException.class,
                () -> parser.parse("{\"errorCode\": null, \"errorMessage\": \"x\"}"));
    }

    @Test
    @DisplayName("a fractional errorCode is malformed")
    void fractionalErrorCodeIsMalformed() {
        assertThrows(MalformedResponseException.class,
                () -> parser.parse("{\"errorCode\": 10.5}"));
    }

    @Test
    @DisplayName("a missing errorMessage falls back but preserves the code")
    void missingErrorMessageFallsBack() {
        MendApiException thrown = assertThrows(MendApiException.class,
                () -> parser.parse(Fixtures.load("error-missing-message.json")));

        assertEquals(1004, thrown.errorCode());
        assertEquals(MendResponseParser.NO_MESSAGE_FALLBACK, thrown.getMessage());
    }

    @Test
    @DisplayName("a null errorMessage falls back")
    void nullErrorMessageFallsBack() {
        MendApiException thrown = assertThrows(MendApiException.class,
                () -> parser.parse("{\"errorCode\": 2001, \"errorMessage\": null}"));

        assertEquals(2001, thrown.errorCode());
        assertEquals(MendResponseParser.NO_MESSAGE_FALLBACK, thrown.getMessage());
    }

    @Test
    @DisplayName("a blank errorMessage falls back")
    void blankErrorMessageFallsBack() {
        MendApiException thrown = assertThrows(MendApiException.class,
                () -> parser.parse("{\"errorCode\": 2002, \"errorMessage\": \"   \"}"));

        assertEquals(MendResponseParser.NO_MESSAGE_FALLBACK, thrown.getMessage());
    }

    @Test
    @DisplayName("a non-textual errorMessage falls back")
    void nonTextualErrorMessageFallsBack() {
        MendApiException thrown = assertThrows(MendApiException.class,
                () -> parser.parse("{\"errorCode\": 2003, \"errorMessage\": {\"nested\": 1}}"));

        assertEquals(MendResponseParser.NO_MESSAGE_FALLBACK, thrown.getMessage());
    }

    // ---------- malformed bodies ----------

    @Test
    @DisplayName("an HTML body is malformed, not a crash")
    void htmlBodyIsMalformed() {
        assertThrows(MalformedResponseException.class,
                () -> parser.parse(Fixtures.load("malformed-html.html")));
    }

    @Test
    @DisplayName("truncated JSON is malformed")
    void truncatedJsonIsMalformed() {
        assertThrows(MalformedResponseException.class,
                () -> parser.parse(Fixtures.load("malformed-truncated.json")));
    }

    @Test
    @DisplayName("a null body is malformed")
    void nullBodyIsMalformed() {
        assertThrows(MalformedResponseException.class, () -> parser.parse(null));
    }

    @Test
    @DisplayName("an empty body is malformed (readTree returns a missing node, it does not throw)")
    void emptyBodyIsMalformed() {
        assertThrows(MalformedResponseException.class, () -> parser.parse(""));
    }

    @Test
    @DisplayName("a whitespace-only body is malformed")
    void whitespaceBodyIsMalformed() {
        assertThrows(MalformedResponseException.class, () -> parser.parse("   \n  "));
    }

    @Test
    @DisplayName("an array root is malformed (Jackson does not throw for this)")
    void arrayRootIsMalformed() {
        assertThrows(MalformedResponseException.class,
                () -> parser.parse(Fixtures.load("malformed-root-array.json")));
    }

    @Test
    @DisplayName("a scalar root is malformed")
    void scalarRootIsMalformed() {
        assertThrows(MalformedResponseException.class, () -> parser.parse("\"just a string\""));
        assertThrows(MalformedResponseException.class, () -> parser.parse("42"));
        assertThrows(MalformedResponseException.class, () -> parser.parse("true"));
    }

    @Test
    @DisplayName("a missing vulnerabilities field is malformed")
    void missingVulnerabilitiesFieldIsMalformed() {
        assertThrows(MalformedResponseException.class,
                () -> parser.parse(Fixtures.load("malformed-missing-field.json")));
    }

    @Test
    @DisplayName("an explicitly null vulnerabilities field is malformed")
    void nullVulnerabilitiesIsMalformed() {
        assertThrows(MalformedResponseException.class,
                () -> parser.parse(Fixtures.load("malformed-vulns-null.json")));
    }

    @Test
    @DisplayName("a non-array vulnerabilities field is malformed")
    void nonArrayVulnerabilitiesIsMalformed() {
        assertThrows(MalformedResponseException.class,
                () -> parser.parse(Fixtures.load("malformed-vulns-object.json")));
    }

    // ---------- leak protection ----------

    @Test
    @DisplayName("no exception in the cause chain reveals the response body or a secret")
    void exceptionsNeverRevealTheBody() {
        String secret = "TOKEN-DO-NOT-LEAK-7b1c";
        String uniqueBodyMarker = "UNIQUE-BODY-MARKER-4d2e";

        String[] hostileBodies = {
                "{ this is not json " + secret + " " + uniqueBodyMarker,
                "<html>" + secret + " " + uniqueBodyMarker + "</html>",
                "{\"vulnerabilities\": null, \"echo\": \"" + secret + " " + uniqueBodyMarker + "\"}",
                "{\"vulnerabilities\": {}, \"echo\": \"" + secret + " " + uniqueBodyMarker + "\"}",
                "{\"other\": \"" + secret + " " + uniqueBodyMarker + "\"}",
                "[\"" + secret + " " + uniqueBodyMarker + "\"]",
                "{\"errorCode\": \"" + secret + "\"}"
        };

        for (String body : hostileBodies) {
            MalformedResponseException thrown = assertThrows(MalformedResponseException.class,
                    () -> parser.parse(body), "expected malformed for body: " + body.length() + " chars");

            for (Throwable t = thrown; t != null; t = t.getCause()) {
                String message = String.valueOf(t.getMessage());
                assertFalse(message.contains(secret),
                        "secret leaked via " + t.getClass().getSimpleName() + ": " + message);
                assertFalse(message.contains(uniqueBodyMarker),
                        "response body leaked via " + t.getClass().getSimpleName() + ": " + message);
            }
        }
    }
}
