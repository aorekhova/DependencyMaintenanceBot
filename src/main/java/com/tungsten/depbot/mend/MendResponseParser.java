package com.tungsten.depbot.mend;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.mend.model.MendErrorResponse;
import com.tungsten.depbot.mend.model.VulnerabilityReport;

/**
 * Interprets a raw Mend response body.
 *
 * <p>This is the only class that sees the response body, and the body never leaves it — not in
 * a return value, not in a log line, and not in an exception message.
 *
 * <p>The order of the checks below is deliberate and is driven by measured Jackson behaviour
 * rather than assumption. In particular {@code readTree} does <em>not</em> throw for an empty
 * body (it returns a missing node) nor for a root that is an array or a scalar, so those cases
 * need explicit guards. Likewise {@code has("vulnerabilities")} returns {@code true} when the
 * field is present with an explicit JSON {@code null}, so presence must be checked with
 * {@code get} plus {@code isNull}.
 */
public final class MendResponseParser {

    static final String NO_MESSAGE_FALLBACK = "Mend reported an error with no message";

    private static final String VULNERABILITIES = "vulnerabilities";
    private static final String ERROR_CODE = "errorCode";
    private static final String ERROR_MESSAGE = "errorMessage";

    /**
     * Source inclusion is already off by default in Jackson 2.18, but disabling it explicitly
     * keeps a future upgrade from quietly inlining the response body into parse-error messages.
     */
    private final ObjectMapper mapper = JsonMapper.builder()
            .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
            .build();

    public VulnerabilityReport parse(String body) {
        if (body == null || body.isBlank()) {
            throw new MalformedResponseException("the response body was empty");
        }

        JsonNode root;
        try {
            root = mapper.readTree(body);
        } catch (JsonProcessingException e) {
            throw new MalformedResponseException("the response body was not valid JSON", e);
        }

        if (root == null || root.isMissingNode()) {
            throw new MalformedResponseException("the response body was empty");
        }
        if (!root.isObject()) {
            throw new MalformedResponseException("the response root was not a JSON object");
        }

        // Must precede the report checks: Mend returns its errors with HTTP 200 and such a body
        // has no vulnerabilities field, so it would otherwise be misreported as malformed.
        if (root.has(ERROR_CODE)) {
            throw toApiException(root);
        }

        JsonNode vulnerabilities = root.get(VULNERABILITIES);
        if (vulnerabilities == null) {
            throw new MalformedResponseException("the response had no vulnerabilities field");
        }
        if (vulnerabilities.isNull()) {
            throw new MalformedResponseException("the vulnerabilities field was null");
        }
        if (!vulnerabilities.isArray()) {
            throw new MalformedResponseException("the vulnerabilities field was not an array");
        }

        try {
            return mapper.treeToValue(root, VulnerabilityReport.class);
        } catch (JsonProcessingException e) {
            throw new MalformedResponseException(
                    "the response did not match the expected report shape", e);
        }
    }

    /**
     * Validates the error envelope before trusting it. An unreadable code is treated as a
     * malformed response rather than reported as error code zero.
     */
    private MendApiException toApiException(JsonNode root) {
        JsonNode codeNode = root.get(ERROR_CODE);
        if (codeNode == null || codeNode.isNull()) {
            throw new MalformedResponseException("the errorCode field was null");
        }
        if (!codeNode.isIntegralNumber() || !codeNode.canConvertToInt()) {
            throw new MalformedResponseException("the errorCode field was not an integer");
        }

        MendErrorResponse error = new MendErrorResponse(codeNode.asInt(), resolveMessage(root));
        return new MendApiException(error.errorCode(), error.errorMessage());
    }

    private static String resolveMessage(JsonNode root) {
        JsonNode messageNode = root.get(ERROR_MESSAGE);
        boolean unusable = messageNode == null
                || messageNode.isNull()
                || !messageNode.isTextual()
                || messageNode.asText().isBlank();
        return unusable ? NO_MESSAGE_FALLBACK : messageNode.asText();
    }
}
