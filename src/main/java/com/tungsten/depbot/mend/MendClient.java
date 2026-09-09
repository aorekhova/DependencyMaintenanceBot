package com.tungsten.depbot.mend;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tungsten.depbot.config.EnvConfig;
import com.tungsten.depbot.mend.model.VulnerabilityReport;

import java.io.IOException;
import java.net.ConnectException;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Calls Mend's {@code getProjectVulnerabilityReport} endpoint.
 *
 * <p>This is the only class that knows Mend's URL and request shape. The request body carries
 * the credentials and is never logged; the response body is handed straight to
 * {@link MendResponseParser} and never appears in a message.
 */
public final class MendClient implements MendGateway {

    public static final String DEFAULT_ENDPOINT = "https://saas.whitesourcesoftware.com/api/v1.4";
    public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(10);
    public static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(30);

    /** Sanity ceiling on the response size. See the note in {@link #fetchVulnerabilityReport}. */
    static final long MAX_RESPONSE_BYTES = 32L * 1024 * 1024;

    private static final String REQUEST_TYPE = "getProjectVulnerabilityReport";

    private final HttpClient httpClient;
    private final URI endpoint;
    private final Duration requestTimeout;
    private final ObjectMapper mapper = new ObjectMapper();
    private final MendResponseParser parser = new MendResponseParser();

    /** Production constructor: the real Mend endpoint and the default request timeout. */
    public MendClient(HttpClient httpClient) {
        this(httpClient, DEFAULT_ENDPOINT, DEFAULT_REQUEST_TIMEOUT);
    }

    /**
     * Test constructor, letting a test aim at a local mock server and shorten the request timeout;
     * a fixed 30-second constant would make the timeout test take 30 seconds.
     *
     * <p>Public so scan-level tests outside this package can drive a whole run over a real socket.
     * Production code uses {@link #MendClient(HttpClient)}.
     */
    public MendClient(HttpClient httpClient, String endpoint, Duration requestTimeout) {
        this.httpClient = httpClient;
        this.endpoint = URI.create(endpoint);
        this.requestTimeout = requestTimeout;
    }

    /**
     * Builds the HTTP client used in production.
     *
     * <p>{@code proxy(ProxySelector.getDefault())} is required for {@code -Dhttps.proxyHost} to
     * have any effect: {@code HttpClient.newHttpClient()} uses no proxy at all and ignores those
     * system properties silently.
     *
     * <p>{@code Redirect.NEVER} is deliberate, not a leftover default. The JDK downgrades a
     * redirected POST to a GET and drops the request body — which is where the credentials are —
     * so a followed redirect would send an unauthenticated request and return a confusing result.
     */
    public static HttpClient defaultHttpClient() {
        return HttpClient.newBuilder()
                .connectTimeout(DEFAULT_CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER)
                .proxy(ProxySelector.getDefault())
                .build();
    }

    @Override
    public VulnerabilityReport fetchVulnerabilityReport(EnvConfig config) {
        HttpRequest request = HttpRequest.newBuilder(endpoint)
                .timeout(requestTimeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        buildRequestBody(config), StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new MendHttpException(classify(e), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new MendHttpException("the request to Mend was interrupted", e);
        }

        int status = response.statusCode();
        if (status >= 300 && status < 400) {
            throw new MendHttpException("Mend API returned HTTP " + status
                    + "; a redirect usually means a proxy or gateway intercepted the request"
                    + " rather than Mend answering it");
        }
        if (status != 200) {
            throw new MendHttpException("Mend API returned HTTP " + status);
        }

        // Partial guard only: a chunked response declares no Content-Length, and the body has
        // already been buffered by the time this runs. It still stops an absurd payload from
        // being parsed. A true cap needs a custom BodySubscriber and is out of scope here.
        long declaredLength = response.headers().firstValueAsLong("content-length").orElse(-1L);
        if (declaredLength > MAX_RESPONSE_BYTES) {
            throw new MalformedResponseException("the response exceeded the supported size limit");
        }

        return parser.parse(response.body());
    }

    /**
     * Turns a transport failure into safe, fixed wording.
     *
     * <p>Extracted as a pure function because two of these categories cannot be produced
     * deterministically through a real socket, and because the cause's own message is unusable:
     * on Windows {@code ConnectException.getMessage()} is {@code null}.
     *
     * <p>Order matters. {@code HttpConnectTimeoutException} extends {@code HttpTimeoutException},
     * and {@code ConnectException} extends {@code IOException}, so the specific cases must be
     * tested first or they become unreachable.
     *
     * <p>A refused connection and an unresolvable host both surface as {@code ConnectException}
     * with a null message, so they deliberately share one honest description rather than
     * claiming "connection refused" for what may be DNS or proxy policy.
     */
    static String classify(IOException failure) {
        if (failure instanceof HttpConnectTimeoutException) {
            return "the connection to the Mend API timed out";
        }
        if (failure instanceof HttpTimeoutException) {
            return "the request to the Mend API timed out";
        }
        if (failure instanceof ConnectException) {
            return "could not reach the Mend API host; check network access and proxy settings"
                    + " (-Dhttps.proxyHost and -Dhttps.proxyPort)";
        }
        return "a network error occurred while calling the Mend API";
    }

    /**
     * Built with Jackson rather than string concatenation: a credential containing a quote,
     * a backslash, or a stray newline would otherwise produce invalid JSON or allow injection.
     */
    private String buildRequestBody(EnvConfig config) {
        ObjectNode body = mapper.createObjectNode();
        body.put("requestType", REQUEST_TYPE);
        body.put("userKey", config.userKey());
        body.put("projectToken", config.projectToken());
        body.put("format", "json");
        body.put("excludeExtraData", true);
        try {
            return mapper.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            // Message deliberately omits the body, which contains the credentials.
            throw new MendHttpException("could not build the Mend request", e);
        }
    }
}
