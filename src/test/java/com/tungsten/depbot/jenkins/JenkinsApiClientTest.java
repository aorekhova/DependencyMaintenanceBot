package com.tungsten.depbot.jenkins;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises {@link JenkinsApiClient} against a local {@link HttpServer} stub standing in for Jenkins.
 *
 * <p><strong>This proves only that our own client builds the request it intends to build.</strong> It
 * does not, and cannot, prove that a real Jenkins 2.204.2 installation accepts this exact multipart
 * shape -- see {@link JenkinsApiClient}'s own class javadoc. That confirmation only comes from an actual
 * manual pilot run -- which is exactly how two real regressions were caught here:
 *
 * <ol>
 *   <li>A multipart part literally named {@code SOURCE_PATCH}, with no {@code file} key in the
 *       {@code json} entry, was silently ignored by the real Jenkins 2.204.2 installation: the build
 *       started, but {@code SOURCE_PATCH} never materialized in the workspace. {@link
 *       #triggerRequestMapsTheFilePartToSourcePatchByName()} parses the actual multipart structure --
 *       not just substring presence -- to keep that regression from coming back unnoticed.</li>
 *   <li>A multipart trigger carrying a core File Parameter is handled by Jenkins 2.204.2's classic,
 *       form-submission-shaped {@code doBuild} path, whose {@code Location} redirects back to the job's
 *       own page instead of a queue item -- even though the build is genuinely, successfully queued and
 *       run. The legacy-fallback tests below (from {@link
 *       #legacyLocationFallsBackToParameterMatchedBuild()} onward) exercise the deterministic,
 *       parameter-matched discovery this client falls back to for exactly that response shape.</li>
 * </ol>
 */
class JenkinsApiClientTest {

    private static final String USERNAME = "bot";
    private static final String TOKEN = "TOKEN-DO-NOT-LEAK-9f3a";
    private static final String JOB_NAME = "WebApplicationDependencyValidation";

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

    private String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private JenkinsApiClient clientFor(HttpServer server) {
        this.server = server;
        server.start();
        httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        JenkinsConfig config = new JenkinsConfig(baseUrl(), JOB_NAME, USERNAME, TOKEN,
                Duration.ofSeconds(5), Duration.ofMillis(50));
        return new JenkinsApiClient(config, httpClient);
    }

    private static void respondJson(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static JenkinsCandidate candidate() {
        return new JenkinsCandidate("baseSha123", "candidateSha456", "diff --git a/x b/x\n+hi\n", "treeSha789");
    }

    private HttpServer newServerWithCrumbOnly() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/crumbIssuer/api/json", exchange -> respondJson(exchange, 200,
                "{\"crumbRequestField\":\"Jenkins-Crumb\",\"crumb\":\"crumb-value-123\"}"));
        return server;
    }

    /**
     * Every trigger calls {@code job/<name>/api/json} first (to read {@code nextBuildNumber}); a build
     * with no interest in legacy fallback just needs it to exist, reporting an empty {@code builds} list.
     */
    private HttpServer newServerWithCrumbAndNextBuildNumber(int nextBuildNumber) throws IOException {
        HttpServer server = newServerWithCrumbOnly();
        server.createContext("/job/" + JOB_NAME + "/api/json", exchange -> respondJson(exchange, 200,
                "{\"nextBuildNumber\":" + nextBuildNumber + ",\"builds\":[]}"));
        return server;
    }

    /** A server answering the full trigger -> queue -> build -> result sequence with a fixed result. */
    private HttpServer fullSequenceServer(String finalResult, AtomicReference<String> capturedBody,
            AtomicReference<String> capturedCrumbHeader, AtomicReference<String> capturedAuth) throws IOException {
        return fullSequenceServer(finalResult, capturedBody, capturedCrumbHeader, capturedAuth, new AtomicReference<>());
    }

    private HttpServer fullSequenceServer(String finalResult, AtomicReference<String> capturedBody,
            AtomicReference<String> capturedCrumbHeader, AtomicReference<String> capturedAuth,
            AtomicReference<String> capturedContentType) throws IOException {
        HttpServer server = newServerWithCrumbAndNextBuildNumber(100);

        server.createContext("/job/" + JOB_NAME + "/build", exchange -> {
            capturedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            capturedCrumbHeader.set(exchange.getRequestHeaders().getFirst("Jenkins-Crumb"));
            capturedAuth.set(exchange.getRequestHeaders().getFirst("Authorization"));
            capturedContentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
            exchange.getResponseHeaders().add("Location",
                    "http://127.0.0.1:" + exchange.getLocalAddress().getPort() + "/queue/item/1/");
            exchange.sendResponseHeaders(201, -1);
            exchange.close();
        });

        server.createContext("/queue/item/1/api/json", exchange -> respondJson(exchange, 200,
                "{\"executable\":{\"number\":7,\"url\":\"http://127.0.0.1:"
                        + exchange.getLocalAddress().getPort() + "/job/" + JOB_NAME + "/7/\"}}"));

        server.createContext("/job/" + JOB_NAME + "/7/api/json", exchange -> respondJson(exchange, 200,
                "{\"building\":false,\"result\":\"" + finalResult + "\",\"duration\":4321}"));

        return server;
    }

    @Test
    @DisplayName("the trigger request carries the patch bytes and the two SHAs somewhere in the multipart body")
    void triggerRequestHasTheExpectedMultipartShape() throws IOException {
        AtomicReference<String> body = new AtomicReference<>();
        AtomicReference<String> crumb = new AtomicReference<>();
        AtomicReference<String> auth = new AtomicReference<>();
        JenkinsApiClient client = clientFor(fullSequenceServer("SUCCESS", body, crumb, auth));

        client.triggerBuild(candidate());

        assertTrue(body.get().contains("diff --git a/x b/x"), body.get());
        assertTrue(body.get().contains("name=\"json\""), body.get());
        assertTrue(body.get().contains("BASE_COMMIT_SHA"), body.get());
        assertTrue(body.get().contains("baseSha123"), body.get());
        assertTrue(body.get().contains("EXPECTED_TREE_SHA"), body.get());
        assertTrue(body.get().contains("treeSha789"), body.get());
    }

    /**
     * The regression test for the real-pilot-caught bug: a multipart part literally named
     * {@code SOURCE_PATCH} is not how Jenkins core resolves a File Parameter's bytes, and a test that
     * only checked for that substring's presence passed anyway -- it never actually verified the mapping
     * Jenkins itself needs. This parses the real multipart structure and the real {@code json} field.
     */
    @Test
    @DisplayName("the json field maps SOURCE_PATCH to the file0 part by name, not by a literally-named multipart field")
    void triggerRequestMapsTheFilePartToSourcePatchByName() throws IOException {
        AtomicReference<String> body = new AtomicReference<>();
        AtomicReference<String> crumb = new AtomicReference<>();
        AtomicReference<String> auth = new AtomicReference<>();
        AtomicReference<String> contentType = new AtomicReference<>();
        JenkinsApiClient client = clientFor(fullSequenceServer("SUCCESS", body, crumb, auth, contentType));

        client.triggerBuild(candidate());

        String boundary = extractBoundary(contentType.get());
        Map<String, MultipartPart> parts = parseMultipart(body.get(), boundary);

        assertTrue(parts.containsKey("file0"), "expected a multipart field named file0: " + parts.keySet());
        assertEquals(candidate().sourcePatch(), parts.get("file0").content());
        assertFalse(parts.containsKey("SOURCE_PATCH"),
                "Jenkins does not bind a File Parameter to a multipart field literally named after the "
                        + "parameter -- naming it that way is what broke the real pilot");

        assertTrue(parts.containsKey("json"), "expected a multipart field named json: " + parts.keySet());
        JsonNode parametersJson = new JsonMapper().readTree(parts.get("json").content());
        JsonNode sourcePatchParameter = findParameter(parametersJson, "SOURCE_PATCH");
        assertEquals("file0", sourcePatchParameter.path("file").asText(null),
                "the SOURCE_PATCH parameter definition must point at the file0 multipart field: "
                        + parametersJson);
        assertNull(sourcePatchParameter.get("value"),
                "a File Parameter is referenced by \"file\", never given an inline \"value\": " + parametersJson);

        JsonNode baseCommitParameter = findParameter(parametersJson, "BASE_COMMIT_SHA");
        assertEquals("baseSha123", baseCommitParameter.path("value").asText(null));
        JsonNode expectedTreeParameter = findParameter(parametersJson, "EXPECTED_TREE_SHA");
        assertEquals("treeSha789", expectedTreeParameter.path("value").asText(null));
    }

    private static JsonNode findParameter(JsonNode parametersJson, String name) {
        for (JsonNode parameter : parametersJson.path("parameter")) {
            if (name.equals(parameter.path("name").asText())) {
                return parameter;
            }
        }
        throw new AssertionError("no parameter named " + name + " in " + parametersJson);
    }

    private static String extractBoundary(String contentType) {
        Matcher matcher = Pattern.compile("boundary=(.+)$").matcher(contentType);
        assertTrue(matcher.find(), "no boundary in Content-Type: " + contentType);
        return matcher.group(1);
    }

    private record MultipartPart(Map<String, String> headers, String content) {
    }

    /** A minimal multipart/form-data parser -- enough to map field name to body content for these tests. */
    private static Map<String, MultipartPart> parseMultipart(String body, String boundary) {
        Map<String, MultipartPart> parts = new LinkedHashMap<>();
        String delimiter = "--" + boundary;
        for (String rawPart : body.split(Pattern.quote(delimiter))) {
            if (rawPart.isBlank() || rawPart.strip().equals("--")) {
                continue;
            }
            String trimmed = rawPart.startsWith("\r\n") ? rawPart.substring(2) : rawPart;
            int headerEnd = trimmed.indexOf("\r\n\r\n");
            if (headerEnd < 0) {
                continue;
            }
            String headerBlock = trimmed.substring(0, headerEnd);
            String content = trimmed.substring(headerEnd + 4);
            if (content.endsWith("\r\n")) {
                content = content.substring(0, content.length() - 2);
            }

            Map<String, String> headers = new LinkedHashMap<>();
            for (String headerLine : headerBlock.split("\r\n")) {
                int colon = headerLine.indexOf(':');
                if (colon > 0) {
                    headers.put(headerLine.substring(0, colon).strip(), headerLine.substring(colon + 1).strip());
                }
            }

            String disposition = headers.getOrDefault("Content-Disposition", "");
            Matcher nameMatcher = Pattern.compile("name=\"([^\"]+)\"").matcher(disposition);
            if (nameMatcher.find()) {
                parts.put(nameMatcher.group(1), new MultipartPart(headers, content));
            }
        }
        return parts;
    }

    @Test
    @DisplayName("the CSRF crumb is requested and attached to the trigger request")
    void crumbIsRequestedAndAttached() throws IOException {
        AtomicReference<String> body = new AtomicReference<>();
        AtomicReference<String> crumb = new AtomicReference<>();
        AtomicReference<String> auth = new AtomicReference<>();
        JenkinsApiClient client = clientFor(fullSequenceServer("SUCCESS", body, crumb, auth));

        client.triggerBuild(candidate());

        assertEquals("crumb-value-123", crumb.get());
    }

    @Test
    @DisplayName("credentials travel only in the Authorization header, in Basic form, never elsewhere")
    void credentialsTravelOnlyInTheAuthorizationHeader() throws IOException {
        AtomicReference<String> body = new AtomicReference<>();
        AtomicReference<String> crumb = new AtomicReference<>();
        AtomicReference<String> auth = new AtomicReference<>();
        JenkinsApiClient client = clientFor(fullSequenceServer("SUCCESS", body, crumb, auth));

        client.triggerBuild(candidate());

        assertTrue(auth.get() != null && auth.get().startsWith("Basic "), auth.get());
        assertFalse(body.get().contains(TOKEN), "the token must never appear in the request body");
    }

    @Test
    @DisplayName("a successful build resolves through the queue item to the real build and reports SUCCESS")
    void successfulBuildResolvesThroughTheQueue() throws IOException {
        AtomicReference<String> body = new AtomicReference<>();
        AtomicReference<String> crumb = new AtomicReference<>();
        AtomicReference<String> auth = new AtomicReference<>();
        JenkinsApiClient client = clientFor(fullSequenceServer("SUCCESS", body, crumb, auth));

        JenkinsBuildRef ref = client.triggerBuild(candidate());
        JenkinsBuildResult result = client.waitForCompletion(ref, Duration.ofSeconds(5), Duration.ofMillis(20), null);

        assertEquals(JenkinsValidationStatus.SUCCESS, result.status());
        assertEquals(7, result.buildNumber());
        assertTrue(result.buildUrl().contains("/job/" + JOB_NAME + "/7/"), result.buildUrl());
    }

    @Test
    @DisplayName("FAILURE, ABORTED and UNSTABLE all map to their own distinct status")
    void otherResultsMapCorrectly() throws IOException {
        record Case(String jenkinsResult, JenkinsValidationStatus expected) {
        }
        for (Case testCase : new Case[] {
                new Case("FAILURE", JenkinsValidationStatus.FAILED),
                new Case("ABORTED", JenkinsValidationStatus.ABORTED),
                new Case("UNSTABLE", JenkinsValidationStatus.UNSTABLE)}) {
            AtomicReference<String> body = new AtomicReference<>();
            AtomicReference<String> crumb = new AtomicReference<>();
            AtomicReference<String> auth = new AtomicReference<>();
            JenkinsApiClient client = clientFor(fullSequenceServer(testCase.jenkinsResult(), body, crumb, auth));

            JenkinsBuildRef ref = client.triggerBuild(candidate());
            JenkinsBuildResult result =
                    client.waitForCompletion(ref, Duration.ofSeconds(5), Duration.ofMillis(20), null);

            assertEquals(testCase.expected(), result.status());
            tearDown();
        }
    }

    @Test
    @DisplayName("a relative Location header is resolved against the request URI and the queue -> build "
            + "-> terminal result flow completes")
    void relativeLocationHeaderResolvesThroughTheFullFlow() throws IOException {
        HttpServer server = newServerWithCrumbAndNextBuildNumber(100);
        server.createContext("/job/" + JOB_NAME + "/build", exchange -> {
            // Deliberately relative -- RFC 7231 always allowed this, and real servers do send it.
            exchange.getResponseHeaders().add("Location", "/queue/item/123/");
            exchange.sendResponseHeaders(201, -1);
            exchange.close();
        });
        server.createContext("/queue/item/123/api/json", exchange -> respondJson(exchange, 200,
                "{\"executable\":{\"number\":9,\"url\":\"http://127.0.0.1:"
                        + exchange.getLocalAddress().getPort() + "/job/" + JOB_NAME + "/9/\"}}"));
        server.createContext("/job/" + JOB_NAME + "/9/api/json", exchange -> respondJson(exchange, 200,
                "{\"building\":false,\"result\":\"SUCCESS\",\"duration\":1000}"));
        JenkinsApiClient client = clientFor(server);

        JenkinsBuildRef ref = client.triggerBuild(candidate());
        assertTrue(ref.queueItemUrl().startsWith("http://127.0.0.1:"),
                "a relative Location must be resolved to an absolute URI: " + ref.queueItemUrl());
        assertTrue(ref.queueItemUrl().contains("/queue/item/123/"), ref.queueItemUrl());

        JenkinsBuildResult result = client.waitForCompletion(ref, Duration.ofSeconds(5), Duration.ofMillis(20), null);

        assertEquals(JenkinsValidationStatus.SUCCESS, result.status());
        assertEquals(9, result.buildNumber());
    }

    @Test
    @DisplayName("a missing Location header fails closed, rather than polling anything")
    void missingLocationHeaderFailsClosed() throws IOException {
        HttpServer server = newServerWithCrumbAndNextBuildNumber(1);
        server.createContext("/job/" + JOB_NAME + "/build", exchange -> {
            exchange.sendResponseHeaders(201, -1);
            exchange.close();
        });
        JenkinsApiClient client = clientFor(server);

        JenkinsValidationException thrown =
                assertThrows(JenkinsValidationException.class, () -> client.triggerBuild(candidate()));
        assertTrue(thrown.getMessage().contains("Location"), thrown.getMessage());
    }

    @Test
    @DisplayName("a Location that is neither a queue item nor the job page fails closed")
    void trulyUnrelatedLocationFailsClosed() throws IOException {
        HttpServer server = newServerWithCrumbAndNextBuildNumber(1);
        server.createContext("/job/" + JOB_NAME + "/build", exchange -> {
            exchange.getResponseHeaders().add("Location",
                    "http://127.0.0.1:" + exchange.getLocalAddress().getPort() + "/something/totally/unrelated/");
            exchange.sendResponseHeaders(201, -1);
            exchange.close();
        });
        JenkinsApiClient client = clientFor(server);

        JenkinsValidationException thrown =
                assertThrows(JenkinsValidationException.class, () -> client.triggerBuild(candidate()));
        assertTrue(thrown.getMessage().contains("neither"), thrown.getMessage());
    }

    // ---- legacy fallback: Location resolves to the job page, not a queue item -----------------------

    private void addJobPageLegacyLocation(HttpServer server) {
        server.createContext("/job/" + JOB_NAME + "/build", exchange -> {
            exchange.getResponseHeaders().add("Location",
                    "http://127.0.0.1:" + exchange.getLocalAddress().getPort() + "/job/" + JOB_NAME + "/");
            exchange.sendResponseHeaders(201, -1);
            exchange.close();
        });
    }

    private static String buildWithParameters(String result, boolean building, String baseCommitSha, String expectedTreeSha) {
        return "{\"building\":" + building + ",\"result\":" + (result == null ? "null" : "\"" + result + "\"")
                + ",\"duration\":2000,\"actions\":[{\"parameters\":["
                + "{\"name\":\"BASE_COMMIT_SHA\",\"value\":\"" + baseCommitSha + "\"},"
                + "{\"name\":\"EXPECTED_TREE_SHA\",\"value\":\"" + expectedTreeSha + "\"}]}]}";
    }

    /**
     * The exact real-pilot-confirmed sequence: {@code Location} points at the job page; this client falls
     * back to the {@code nextBuildNumber} it read before triggering, finds the one new build whose own
     * {@code BASE_COMMIT_SHA}/{@code EXPECTED_TREE_SHA} build parameters match this candidate exactly, and
     * continues the existing terminal-result polling from there.
     */
    @Test
    @DisplayName("a legacy job-page Location falls back to nextBuildNumber plus an exact parameter match, then SUCCESS")
    void legacyLocationFallsBackToParameterMatchedBuild() throws IOException {
        HttpServer server = newServerWithCrumbOnly();
        server.createContext("/job/" + JOB_NAME + "/api/json", exchange -> respondJson(exchange, 200,
                "{\"nextBuildNumber\":50,\"builds\":[{\"number\":50,\"url\":\"http://127.0.0.1:"
                        + exchange.getLocalAddress().getPort() + "/job/" + JOB_NAME + "/50/\"}]}"));
        addJobPageLegacyLocation(server);
        server.createContext("/job/" + JOB_NAME + "/50/api/json", exchange -> respondJson(exchange, 200,
                buildWithParameters("SUCCESS", false, "baseSha123", "treeSha789")));
        JenkinsApiClient client = clientFor(server);

        JenkinsBuildRef ref = client.triggerBuild(candidate());
        assertTrue(ref.isLegacyFallback(), "a job-page Location must switch this ref into legacy fallback mode");
        assertNull(ref.queueItemUrl());

        JenkinsBuildResult result = client.waitForCompletion(ref, Duration.ofSeconds(5), Duration.ofMillis(20), null);

        assertEquals(JenkinsValidationStatus.SUCCESS, result.status());
        assertEquals(50, result.buildNumber());
    }

    @Test
    @DisplayName("during legacy fallback, an unrelated concurrent build with different parameters is ignored")
    void unrelatedConcurrentBuildIsIgnoredDuringLegacyFallback() throws IOException {
        HttpServer server = newServerWithCrumbOnly();
        addJobPageLegacyLocation(server);
        server.createContext("/job/" + JOB_NAME + "/api/json", exchange -> respondJson(exchange, 200,
                "{\"nextBuildNumber\":50,\"builds\":["
                        + "{\"number\":50,\"url\":\"http://127.0.0.1:" + exchange.getLocalAddress().getPort() + "/job/" + JOB_NAME + "/50/\"},"
                        + "{\"number\":51,\"url\":\"http://127.0.0.1:" + exchange.getLocalAddress().getPort() + "/job/" + JOB_NAME + "/51/\"}]}"));
        // 50 is someone else's unrelated, concurrent trigger -- different parameters entirely.
        server.createContext("/job/" + JOB_NAME + "/50/api/json", exchange -> respondJson(exchange, 200,
                buildWithParameters("SUCCESS", false, "someone-elses-base", "someone-elses-tree")));
        // 51 is genuinely ours.
        server.createContext("/job/" + JOB_NAME + "/51/api/json", exchange -> respondJson(exchange, 200,
                buildWithParameters("SUCCESS", false, "baseSha123", "treeSha789")));
        JenkinsApiClient client = clientFor(server);

        JenkinsBuildRef ref = client.triggerBuild(candidate());
        JenkinsBuildResult result = client.waitForCompletion(ref, Duration.ofSeconds(5), Duration.ofMillis(20), null);

        assertEquals(51, result.buildNumber(),
                "must correlate by build parameters, never just pick the lowest/first new build number");
    }

    @Test
    @DisplayName("an ambiguous parameter match during legacy fallback fails closed rather than guessing")
    void ambiguousParameterMatchFailsClosed() throws IOException {
        HttpServer server = newServerWithCrumbOnly();
        addJobPageLegacyLocation(server);
        server.createContext("/job/" + JOB_NAME + "/api/json", exchange -> respondJson(exchange, 200,
                "{\"nextBuildNumber\":50,\"builds\":["
                        + "{\"number\":50,\"url\":\"http://127.0.0.1:" + exchange.getLocalAddress().getPort() + "/job/" + JOB_NAME + "/50/\"},"
                        + "{\"number\":51,\"url\":\"http://127.0.0.1:" + exchange.getLocalAddress().getPort() + "/job/" + JOB_NAME + "/51/\"}]}"));
        // Both builds, implausibly but possibly, carry exactly the same parameters -- this client must
        // never silently pick one.
        server.createContext("/job/" + JOB_NAME + "/50/api/json", exchange -> respondJson(exchange, 200,
                buildWithParameters("SUCCESS", false, "baseSha123", "treeSha789")));
        server.createContext("/job/" + JOB_NAME + "/51/api/json", exchange -> respondJson(exchange, 200,
                buildWithParameters("SUCCESS", false, "baseSha123", "treeSha789")));
        JenkinsApiClient client = clientFor(server);

        JenkinsBuildRef ref = client.triggerBuild(candidate());
        JenkinsBuildResult result = client.waitForCompletion(ref, Duration.ofSeconds(5), Duration.ofMillis(20), null);

        assertEquals(JenkinsValidationStatus.FAILED, result.status());
        assertTrue(result.resultSummary() != null && result.resultSummary().contains("cannot safely determine"),
                result.resultSummary());
    }

    @Test
    @DisplayName("no matching build appearing before the timeout elapses is reported as TIMED_OUT")
    void noMatchingBuildBeforeTimeoutIsTimedOut() throws IOException {
        HttpServer server = newServerWithCrumbAndNextBuildNumber(50);
        addJobPageLegacyLocation(server);
        // The job api/json context from newServerWithCrumbAndNextBuildNumber already reports an empty
        // builds list forever -- nothing ever appears to match.
        JenkinsApiClient client = clientFor(server);

        JenkinsBuildRef ref = client.triggerBuild(candidate());
        long startedAt = System.nanoTime();
        JenkinsBuildResult result =
                client.waitForCompletion(ref, Duration.ofMillis(300), Duration.ofMillis(50), null);
        long elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000;

        assertEquals(JenkinsValidationStatus.TIMED_OUT, result.status());
        assertTrue(elapsedMillis < 5000, "the timeout must be respected, not the default: " + elapsedMillis);
    }

    @Test
    @DisplayName("a build still running when the timeout elapses is reported as TIMED_OUT, not thrown")
    void stillBuildingAtTimeoutIsTimedOut() throws IOException {
        HttpServer server = newServerWithCrumbAndNextBuildNumber(100);
        server.createContext("/job/" + JOB_NAME + "/build", exchange -> {
            exchange.getResponseHeaders().add("Location",
                    "http://127.0.0.1:" + exchange.getLocalAddress().getPort() + "/queue/item/1/");
            exchange.sendResponseHeaders(201, -1);
            exchange.close();
        });
        server.createContext("/queue/item/1/api/json", exchange -> respondJson(exchange, 200,
                "{\"executable\":{\"number\":7,\"url\":\"http://127.0.0.1:"
                        + exchange.getLocalAddress().getPort() + "/job/" + JOB_NAME + "/7/\"}}"));
        server.createContext("/job/" + JOB_NAME + "/7/api/json", exchange -> respondJson(exchange, 200,
                "{\"building\":true}"));
        JenkinsApiClient client = clientFor(server);

        JenkinsBuildRef ref = client.triggerBuild(candidate());
        long startedAt = System.nanoTime();
        JenkinsBuildResult result =
                client.waitForCompletion(ref, Duration.ofMillis(300), Duration.ofMillis(50), null);
        long elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000;

        assertEquals(JenkinsValidationStatus.TIMED_OUT, result.status());
        assertTrue(elapsedMillis < 5000, "the timeout must be respected, not the default: " + elapsedMillis);
    }
}
