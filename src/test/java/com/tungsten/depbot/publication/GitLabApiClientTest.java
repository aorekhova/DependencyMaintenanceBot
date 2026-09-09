package com.tungsten.depbot.publication;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises {@link GitLabApiClient} against a local {@link HttpServer} -- the real GitLab REST API is
 * never called by this test tree. Every server binds {@code 127.0.0.1} on an ephemeral port.
 *
 * <p>Proves the wire format this application actually sends: the private token only ever in the {@code
 * PRIVATE-TOKEN} header, never in a URL or a request body; every "find" query omits {@code state=opened}
 * so a closed/merged object is discovered exactly as reliably as an open one; more than one match throws
 * rather than picking one; error and malformed-response handling never leaks response bodies containing
 * the token.
 */
class GitLabApiClientTest {

    private static final String PROJECT_TOKEN = "glpat-DO-NOT-LEAK-9f3a";

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

    private GitLabApiClient clientFor(HttpHandler handler) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", handler);
        server.start();
        httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        GitLabConfig config = new GitLabConfig(baseUrl, "123", PROJECT_TOKEN, "origin");
        return new GitLabApiClient(config, httpClient);
    }

    private static void respondJson(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    // ---- fetchProject ------------------------------------------------------------------------------

    @Test
    @DisplayName("fetchProject hits GET /api/v4/projects/<id> and parses path_with_namespace")
    void fetchProjectParsesPathWithNamespace() throws Exception {
        AtomicReference<String> capturedPath = new AtomicReference<>();
        AtomicReference<String> capturedToken = new AtomicReference<>();
        GitLabApiClient client = clientFor(exchange -> {
            capturedPath.set(exchange.getRequestURI().getPath());
            capturedToken.set(exchange.getRequestHeaders().getFirst("PRIVATE-TOKEN"));
            respondJson(exchange, 200,
                    "{\"id\":123,\"path_with_namespace\":\"group/webapp\",\"web_url\":\"http://x/group/webapp\"}");
        });

        ProjectMetadata project = client.fetchProject();

        assertEquals("/api/v4/projects/123", capturedPath.get());
        assertEquals(PROJECT_TOKEN, capturedToken.get());
        assertEquals("group/webapp", project.pathWithNamespace());
    }

    // ---- merge requests ------------------------------------------------------------------------------

    @Test
    @DisplayName("findMergeRequestBySourceBranch never restricts to state=opened -- closed/merged must be discoverable")
    void findMergeRequestNeverRestrictsToOpenedState() throws Exception {
        AtomicReference<String> capturedQuery = new AtomicReference<>();
        GitLabApiClient client = clientFor(exchange -> {
            capturedQuery.set(exchange.getRequestURI().getQuery());
            respondJson(exchange, 200, "[{\"iid\":7,\"web_url\":\"http://x/7\",\"state\":\"closed\"}]");
        });

        Optional<MergeRequestRef> found = client.findMergeRequestBySourceBranch("remediation/run1/branch");

        assertFalse(capturedQuery.get().contains("state=opened"), capturedQuery.get());
        assertTrue(found.isPresent());
        assertEquals(MergeRequestState.CLOSED, found.get().state());
        assertEquals(7, found.get().iid());
    }

    @Test
    @DisplayName("a merged merge request is mapped to MergeRequestState.MERGED")
    void mergedStateIsMapped() throws Exception {
        GitLabApiClient client = clientFor(exchange ->
                respondJson(exchange, 200, "[{\"iid\":8,\"web_url\":\"http://x/8\",\"state\":\"merged\"}]"));

        Optional<MergeRequestRef> found = client.findMergeRequestBySourceBranch("remediation/run1/branch");

        assertEquals(MergeRequestState.MERGED, found.get().state());
    }

    @Test
    @DisplayName("more than one merge request matching the source branch throws rather than guessing")
    void moreThanOneMergeRequestThrows() throws Exception {
        GitLabApiClient client = clientFor(exchange -> respondJson(exchange, 200,
                "[{\"iid\":1,\"web_url\":\"http://x/1\",\"state\":\"opened\"},"
                        + "{\"iid\":2,\"web_url\":\"http://x/2\",\"state\":\"opened\"}]"));

        GitLabPublicationException exception = assertThrows(GitLabPublicationException.class,
                () -> client.findMergeRequestBySourceBranch("remediation/run1/branch"));
        assertTrue(exception.getMessage().contains("Found 2 merge requests"), exception.getMessage());
    }

    @Test
    @DisplayName("createMergeRequest posts the expected body and returns an OPEN reference")
    void createMergeRequestPostsExpectedBody() throws Exception {
        AtomicReference<String> capturedBody = new AtomicReference<>();
        AtomicReference<String> capturedMethod = new AtomicReference<>();
        GitLabApiClient client = clientFor(exchange -> {
            capturedMethod.set(exchange.getRequestMethod());
            capturedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            respondJson(exchange, 201, "{\"iid\":9,\"web_url\":\"http://x/9\"}");
        });

        MergeRequestRef created = client.createMergeRequest(
                "remediation/run1/branch", "hotfix-2026.1", "title", "description");

        assertEquals("POST", capturedMethod.get());
        assertTrue(capturedBody.get().contains("\"source_branch\":\"remediation/run1/branch\""), capturedBody.get());
        assertTrue(capturedBody.get().contains("\"target_branch\":\"hotfix-2026.1\""), capturedBody.get());
        assertEquals(MergeRequestState.OPEN, created.state());
        assertEquals(9, created.iid());
    }

    // ---- issues --------------------------------------------------------------------------------------

    @Test
    @DisplayName("findIssueContaining never restricts to state=opened -- a closed issue must be discoverable")
    void findIssueNeverRestrictsToOpenedState() throws Exception {
        String marker = "<!-- depbot-human-review:run1:group -->";
        AtomicReference<String> capturedQuery = new AtomicReference<>();
        GitLabApiClient client = clientFor(exchange -> {
            capturedQuery.set(exchange.getRequestURI().getQuery());
            respondJson(exchange, 200, "[{\"iid\":5,\"web_url\":\"http://x/5\",\"state\":\"closed\","
                    + "\"description\":\"" + marker + "\"}]");
        });

        Optional<IssueRef> found = client.findIssueContaining(marker);

        assertFalse(capturedQuery.get().contains("state=opened"), capturedQuery.get());
        assertTrue(found.isPresent());
        assertEquals(IssueState.CLOSED, found.get().state());
    }

    @Test
    @DisplayName("more than one issue matching the marker throws rather than guessing")
    void moreThanOneIssueThrows() throws Exception {
        String marker = "<!-- depbot-human-review:run1:group -->";
        GitLabApiClient client = clientFor(exchange -> respondJson(exchange, 200,
                "[{\"iid\":1,\"web_url\":\"http://x/1\",\"state\":\"opened\",\"description\":\"" + marker + "\"},"
                        + "{\"iid\":2,\"web_url\":\"http://x/2\",\"state\":\"closed\",\"description\":\"" + marker + "\"}]"));

        GitLabPublicationException exception =
                assertThrows(GitLabPublicationException.class, () -> client.findIssueContaining(marker));
        assertTrue(exception.getMessage().contains("Found 2 issues"), exception.getMessage());
    }

    @Test
    @DisplayName("createIssue posts the expected title/description and returns an OPEN reference")
    void createIssuePostsExpectedBody() throws Exception {
        AtomicReference<String> capturedBody = new AtomicReference<>();
        GitLabApiClient client = clientFor(exchange -> {
            capturedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            respondJson(exchange, 201, "{\"iid\":11,\"web_url\":\"http://x/11\"}");
        });

        IssueRef created = client.createIssue("title", "description");

        assertTrue(capturedBody.get().contains("\"title\":\"title\""), capturedBody.get());
        assertEquals(IssueState.OPEN, created.state());
    }

    // ---- commit comments -----------------------------------------------------------------------------

    @Test
    @DisplayName("postCommitComment hits the commit's own comments endpoint")
    void postCommitCommentHitsExpectedEndpoint() throws Exception {
        AtomicReference<String> capturedPath = new AtomicReference<>();
        GitLabApiClient client = clientFor(exchange -> {
            capturedPath.set(exchange.getRequestURI().getPath());
            respondJson(exchange, 201, "{}");
        });

        client.postCommitComment("abc123", "report body");

        assertEquals("/api/v4/projects/123/repository/commits/abc123/comments", capturedPath.get());
    }

    // ---- auth / errors ---------------------------------------------------------------------------------

    @Test
    @DisplayName("the private token is sent only in the PRIVATE-TOKEN header, never in the URL")
    void tokenNeverAppearsInUrl() throws Exception {
        AtomicReference<String> capturedUri = new AtomicReference<>();
        GitLabApiClient client = clientFor(exchange -> {
            capturedUri.set(exchange.getRequestURI().toString());
            respondJson(exchange, 200, "{\"id\":123,\"path_with_namespace\":\"group/webapp\"}");
        });

        client.fetchProject();

        assertFalse(capturedUri.get().contains(PROJECT_TOKEN), capturedUri.get());
    }

    @Test
    @DisplayName("an authentication failure raises GitLabPublicationException without leaking the token")
    void authFailureRaisesException() throws Exception {
        GitLabApiClient client = clientFor(exchange -> respondJson(exchange, 401, "{\"message\":\"401 Unauthorized\"}"));

        GitLabPublicationException exception = assertThrows(GitLabPublicationException.class, client::fetchProject);
        assertFalse(exception.getMessage().contains(PROJECT_TOKEN), exception.getMessage());
    }

    @Test
    @DisplayName("a server error raises GitLabPublicationException")
    void serverErrorRaisesException() throws Exception {
        GitLabApiClient client = clientFor(exchange -> respondJson(exchange, 500, "{\"message\":\"internal error\"}"));

        assertThrows(GitLabPublicationException.class, client::fetchProject);
    }

    @Test
    @DisplayName("a malformed (non-JSON) response raises GitLabPublicationException, not a parser crash")
    void malformedResponseRaisesException() throws Exception {
        GitLabApiClient client = clientFor(exchange -> respondJson(exchange, 200, "not json at all"));

        assertThrows(GitLabPublicationException.class, client::fetchProject);
    }
}
