package com.tungsten.depbot.mend;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.tungsten.depbot.Fixtures;
import com.tungsten.depbot.config.EnvConfig;
import com.tungsten.depbot.mend.model.VulnerabilityReport;
import com.tungsten.depbot.report.SeverityCounts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises {@link MendClient} against a local {@link HttpServer}.
 *
 * <p>Every server binds 127.0.0.1 on an ephemeral port and every client is aimed at that port.
 * The real Mend hostname never appears in this file, which {@code NoRealMendEndpointTest}
 * enforces for the whole test tree.
 */
class MendClientIntegrationTest {

    private static final String PATH = "/api/v1.4";
    private static final String USER_KEY = "USERKEY-DO-NOT-LEAK-9f3a";
    private static final String TOKEN = "TOKEN-DO-NOT-LEAK-7b1c";
    private static final EnvConfig CONFIG = new EnvConfig(USER_KEY, TOKEN);

    private HttpServer server;
    private HttpClient httpClient;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
        if (httpClient != null) {
            httpClient.close();
            httpClient = null;
        }
    }

    /** Starts a server on an ephemeral port and returns a client pointed at it. */
    private MendClient clientFor(HttpHandler handler, Duration requestTimeout) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(PATH, handler);
        server.start();

        httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        String endpoint = "http://127.0.0.1:" + server.getAddress().getPort() + PATH;
        return new MendClient(httpClient, endpoint, requestTimeout);
    }

    private MendClient clientFor(HttpHandler handler) throws IOException {
        return clientFor(handler, Duration.ofSeconds(5));
    }

    private static HttpHandler respond(int status, String body) {
        return exchange -> {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        };
    }

    // ---------- success ----------

    @Test
    @DisplayName("a successful report is parsed and counted")
    void successfulReport() throws IOException {
        MendClient client = clientFor(respond(200, Fixtures.load("success-mixed-severities.json")));

        VulnerabilityReport report = client.fetchVulnerabilityReport(CONFIG);
        SeverityCounts counts = SeverityCounts.from(report.vulnerabilities());

        assertEquals(6, counts.total());
        assertEquals(1, counts.criticalCount());
        assertEquals(2, counts.highCount());
    }

    @Test
    @DisplayName("an empty report yields total zero")
    void emptyReport() throws IOException {
        MendClient client = clientFor(respond(200, Fixtures.load("success-empty.json")));

        VulnerabilityReport report = client.fetchVulnerabilityReport(CONFIG);
        assertEquals(0, SeverityCounts.from(report.vulnerabilities()).total());
    }

    // ---------- HTTP status handling ----------

    @Test
    @DisplayName("HTTP 401 becomes a MendHttpException naming the status only")
    void unauthorized() throws IOException {
        MendClient client = clientFor(respond(401, "{\"secretEcho\":\"" + TOKEN + "\"}"));

        MendHttpException thrown = assertThrows(MendHttpException.class,
                () -> client.fetchVulnerabilityReport(CONFIG));

        assertTrue(thrown.getMessage().contains("401"));
        assertFalse(thrown.getMessage().contains(TOKEN), "response body leaked into the message");
    }

    @Test
    @DisplayName("HTTP 500 becomes a MendHttpException")
    void serverError() throws IOException {
        MendClient client = clientFor(respond(500, "internal error"));

        MendHttpException thrown = assertThrows(MendHttpException.class,
                () -> client.fetchVulnerabilityReport(CONFIG));
        assertTrue(thrown.getMessage().contains("500"));
    }

    @Test
    @DisplayName("HTTP 302 is diagnosed as proxy interception, not followed")
    void redirectIsNotFollowed() throws IOException {
        MendClient client = clientFor(exchange -> {
            exchange.getResponseHeaders().add("Location", "http://127.0.0.1:1/elsewhere");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });

        MendHttpException thrown = assertThrows(MendHttpException.class,
                () -> client.fetchVulnerabilityReport(CONFIG));

        assertTrue(thrown.getMessage().contains("302"));
        assertTrue(thrown.getMessage().contains("proxy"),
                "a redirect should hint at interception: " + thrown.getMessage());
    }

    // ---------- body handling ----------

    @Test
    @DisplayName("an in-band error becomes a MendApiException")
    void inBandError() throws IOException {
        MendClient client = clientFor(respond(200, Fixtures.load("error-1004.json")));

        MendApiException thrown = assertThrows(MendApiException.class,
                () -> client.fetchVulnerabilityReport(CONFIG));
        assertEquals(1004, thrown.errorCode());
    }

    @Test
    @DisplayName("an HTML body at HTTP 200 becomes a MalformedResponseException")
    void htmlBody() throws IOException {
        MendClient client = clientFor(respond(200, Fixtures.load("malformed-html.html")));

        assertThrows(MalformedResponseException.class,
                () -> client.fetchVulnerabilityReport(CONFIG));
    }

    // ---------- transport failures ----------

    @Test
    @DisplayName("a refused connection is reported without leaking anything")
    void connectionRefused() throws IOException {
        int deadPort;
        try (ServerSocket probe = new ServerSocket(0)) {
            deadPort = probe.getLocalPort();
        } // closed here, so nothing is listening on deadPort

        httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        MendClient client = new MendClient(
                httpClient, "http://127.0.0.1:" + deadPort + PATH, Duration.ofSeconds(5));

        MendHttpException thrown = assertThrows(MendHttpException.class,
                () -> client.fetchVulnerabilityReport(CONFIG));

        assertTrue(thrown.getMessage().contains("could not reach the Mend API host"));
        assertFalse(thrown.getMessage().contains("null"));
        assertFalse(thrown.getMessage().contains(USER_KEY));
    }

    @Test
    @DisplayName("a slow response trips the injectable request timeout quickly")
    void requestTimeout() throws IOException {
        MendClient client = clientFor(exchange -> {
            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        }, Duration.ofMillis(200));

        long startedAt = System.nanoTime();
        MendHttpException thrown = assertThrows(MendHttpException.class,
                () -> client.fetchVulnerabilityReport(CONFIG));
        long elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000;

        assertTrue(thrown.getMessage().contains("timed out"));
        assertTrue(elapsedMillis < 2000,
                "timeout must be injectable, not a fixed 30s constant; took " + elapsedMillis + "ms");
    }

    // ---------- outgoing request verification ----------

    @Test
    @DisplayName("the outgoing request has the exact verified shape")
    void outgoingRequestShape() throws Exception {
        AtomicReference<String> method = new AtomicReference<>();
        AtomicReference<String> path = new AtomicReference<>();
        AtomicReference<String> contentType = new AtomicReference<>();
        AtomicReference<String> accept = new AtomicReference<>();
        AtomicReference<String> body = new AtomicReference<>();
        AtomicReference<String> requestUri = new AtomicReference<>();

        MendClient client = clientFor(exchange -> {
            method.set(exchange.getRequestMethod());
            path.set(exchange.getRequestURI().getPath());
            requestUri.set(exchange.getRequestURI().toString());
            contentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
            accept.set(exchange.getRequestHeaders().getFirst("Accept"));
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            respondEmptyReport(exchange);
        });

        client.fetchVulnerabilityReport(CONFIG);

        assertEquals("POST", method.get());
        assertEquals(PATH, path.get());
        assertEquals("application/json", contentType.get());
        assertEquals("application/json", accept.get());

        JsonNode sent = new ObjectMapper().readTree(body.get());
        assertEquals("getProjectVulnerabilityReport", sent.get("requestType").asText());
        assertEquals("json", sent.get("format").asText());
        assertTrue(sent.get("excludeExtraData").isBoolean());
        assertTrue(sent.get("excludeExtraData").asBoolean());
        assertEquals(USER_KEY, sent.get("userKey").asText());
        assertEquals(TOKEN, sent.get("projectToken").asText());

        // Credentials must travel in the body only, never in the URL.
        assertFalse(requestUri.get().contains(USER_KEY));
        assertFalse(requestUri.get().contains(TOKEN));
    }

    @Test
    @DisplayName("credentials containing JSON metacharacters are escaped, not concatenated")
    void credentialsAreJsonEscaped() throws Exception {
        String awkwardKey = "quote\"backslash\\newline\nend";
        AtomicReference<String> body = new AtomicReference<>();

        MendClient client = clientFor(exchange -> {
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            respondEmptyReport(exchange);
        });

        client.fetchVulnerabilityReport(new EnvConfig(awkwardKey, TOKEN));

        JsonNode sent = new ObjectMapper().readTree(body.get());
        assertEquals(awkwardKey, sent.get("userKey").asText());
    }

    @Test
    @DisplayName("request headers carry no credential values")
    void headersCarryNoCredentials() throws IOException {
        Map<String, String> headers = new HashMap<>();

        MendClient client = clientFor(exchange -> {
            exchange.getRequestHeaders()
                    .forEach((name, values) -> headers.put(name, String.join(",", values)));
            respondEmptyReport(exchange);
        });

        client.fetchVulnerabilityReport(CONFIG);

        assertFalse(headers.isEmpty());
        headers.forEach((name, value) -> {
            assertFalse(value.contains(USER_KEY), "user key leaked in header " + name);
            assertFalse(value.contains(TOKEN), "project token leaked in header " + name);
        });
    }

    @Test
    @DisplayName("the default production endpoint is the documented Mend v1.4 API")
    void defaultEndpointIsConfigured() {
        assertNotNull(MendClient.DEFAULT_ENDPOINT);
        assertTrue(MendClient.DEFAULT_ENDPOINT.startsWith("https://"));
        assertTrue(MendClient.DEFAULT_ENDPOINT.endsWith("/api/v1.4"));
    }

    private static void respondEmptyReport(HttpExchange exchange) throws IOException {
        byte[] bytes = "{\"vulnerabilities\":[]}".getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
