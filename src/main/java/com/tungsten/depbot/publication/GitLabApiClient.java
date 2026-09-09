package com.tungsten.depbot.publication;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Talks to the real GitLab REST API (v4) over HTTPS. Every request carries the private token in the
 * {@code PRIVATE-TOKEN} header only -- never in a URL, never in an exception message, never logged.
 *
 * <p>Not exercised against a real GitLab instance by this application's own test suite -- {@code
 * GitLabPublicationServiceTest} runs entirely against the in-memory {@code FakeGitLabClient} test double,
 * per the standing instruction that no test here ever reaches the network. This class exists so the
 * wiring is real and complete, ready for the first actual publication pilot.
 *
 * <p>The default constructor's {@link HttpClient} trusts the Windows certificate store when running on
 * Windows (see {@link WindowsTrustStore}), so a corporate GitLab instance whose certificate chains up to
 * an internal root CA is reachable without the {@code -Djavax.net.ssl.trustStoreType=Windows-ROOT} JVM
 * startup flags this application previously required -- and without weakening certificate verification in
 * any way.
 */
public final class GitLabApiClient implements GitLabClient {

    private final GitLabConfig config;
    private final HttpClient httpClient;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public GitLabApiClient(GitLabConfig config) {
        this(config, defaultHttpClient());
    }

    private static HttpClient defaultHttpClient() {
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30));
        WindowsTrustStore.sslContext().ifPresent(builder::sslContext);
        return builder.build();
    }

    public GitLabApiClient(GitLabConfig config, HttpClient httpClient) {
        this.config = Objects.requireNonNull(config, "config");
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    }

    @Override
    public ProjectMetadata fetchProject() {
        JsonNode project = getJson("");
        return new ProjectMetadata(
                project.get("id").asText(), project.get("path_with_namespace").asText(),
                project.has("web_url") ? project.get("web_url").asText() : null);
    }

    @Override
    public Optional<MergeRequestRef> findMergeRequestBySourceBranch(String sourceBranch) {
        // Deliberately no &state=opened -- GitLab returns every state (opened/closed/merged/locked) when
        // the parameter is omitted, which is exactly what a retry needs: an already-closed or
        // already-merged Merge Request must be discovered exactly as reliably as an open one.
        JsonNode results = getJsonArray("/merge_requests?source_branch=" + encode(sourceBranch));
        if (results.isEmpty()) {
            return Optional.empty();
        }
        if (results.size() > 1) {
            throw new GitLabPublicationException("Found " + results.size()
                    + " merge requests with source branch \"" + sourceBranch
                    + "\" -- refusing to guess which one is authoritative.");
        }
        JsonNode found = results.get(0);
        return Optional.of(new MergeRequestRef(
                found.get("iid").asInt(), found.get("web_url").asText(), mergeRequestState(found)));
    }

    @Override
    public MergeRequestRef createMergeRequest(
            String sourceBranch, String targetBranch, String title, String description) {
        ObjectNode body = mapper.createObjectNode();
        body.put("source_branch", sourceBranch);
        body.put("target_branch", targetBranch);
        body.put("title", title);
        body.put("description", description);
        body.put("remove_source_branch", false);
        JsonNode created = postJson("/merge_requests", body);
        return new MergeRequestRef(created.get("iid").asInt(), created.get("web_url").asText(), MergeRequestState.OPEN);
    }

    /**
     * {@code "locked"} (GitLab's transient state while a merge is actively in progress) maps to {@link
     * MergeRequestState#OPEN} -- it is neither closed nor merged, and this application only ever reads
     * this value to decide whether it is safe to push/create, for which "not closed, not merged" is the
     * only distinction that matters. Anything else unrecognised falls back to {@code OPEN} for the same
     * reason: never mistaken for the two states this application must never overwrite.
     */
    private static MergeRequestState mergeRequestState(JsonNode mergeRequest) {
        String state = mergeRequest.has("state") ? mergeRequest.get("state").asText() : "";
        return switch (state) {
            case "closed" -> MergeRequestState.CLOSED;
            case "merged" -> MergeRequestState.MERGED;
            default -> MergeRequestState.OPEN;
        };
    }

    @Override
    public void updateMergeRequestDescription(int mergeRequestIid, String description) {
        ObjectNode body = mapper.createObjectNode();
        body.put("description", description);
        putJson("/merge_requests/" + mergeRequestIid, body);
    }

    @Override
    public boolean commitCommentContains(String commitSha, String marker) {
        JsonNode comments = getJsonArray("/repository/commits/" + encode(commitSha) + "/comments");
        for (JsonNode comment : comments) {
            JsonNode note = comment.get("note");
            if (note != null && note.asText("").contains(marker)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void postCommitComment(String commitSha, String body) {
        ObjectNode requestBody = mapper.createObjectNode();
        requestBody.put("note", body);
        postJson("/repository/commits/" + encode(commitSha) + "/comments", requestBody);
    }

    @Override
    public Optional<IssueRef> findIssueContaining(String marker) {
        // Deliberately no &state=opened -- see findMergeRequestBySourceBranch's own comment.
        JsonNode results = getJsonArray("/issues?in=description&search=" + encode(marker));
        List<JsonNode> matches = new ArrayList<>();
        for (JsonNode issue : results) {
            JsonNode description = issue.get("description");
            if (description != null && description.asText("").contains(marker)) {
                matches.add(issue);
            }
        }
        if (matches.isEmpty()) {
            return Optional.empty();
        }
        if (matches.size() > 1) {
            throw new GitLabPublicationException("Found " + matches.size()
                    + " issues matching marker \"" + marker + "\" -- refusing to guess which one is authoritative.");
        }
        JsonNode found = matches.get(0);
        return Optional.of(new IssueRef(found.get("iid").asInt(), found.get("web_url").asText(), issueState(found)));
    }

    @Override
    public IssueRef createIssue(String title, String description) {
        ObjectNode body = mapper.createObjectNode();
        body.put("title", title);
        body.put("description", description);
        JsonNode created = postJson("/issues", body);
        return new IssueRef(created.get("iid").asInt(), created.get("web_url").asText(), IssueState.OPEN);
    }

    private static IssueState issueState(JsonNode issue) {
        String state = issue.has("state") ? issue.get("state").asText() : "";
        return "closed".equals(state) ? IssueState.CLOSED : IssueState.OPEN;
    }

    private JsonNode getJson(String path) {
        return send(HttpRequest.newBuilder(uri(path)).GET(), 200);
    }

    private JsonNode getJsonArray(String path) {
        return send(HttpRequest.newBuilder(uri(path)).GET(), 200);
    }

    private JsonNode postJson(String path, ObjectNode body) {
        return send(HttpRequest.newBuilder(uri(path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8)), 200, 201);
    }

    private JsonNode putJson(String path, ObjectNode body) {
        return send(HttpRequest.newBuilder(uri(path))
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8)), 200);
    }

    private JsonNode send(HttpRequest.Builder requestBuilder, int... acceptedStatusCodes) {
        HttpRequest request = requestBuilder
                .header("PRIVATE-TOKEN", config.privateToken())
                .timeout(Duration.ofSeconds(60))
                .build();

        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new GitLabPublicationException(
                    "Could not reach GitLab at " + safeUri(request.uri()) + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new GitLabPublicationException(
                    "Interrupted while waiting for GitLab at " + safeUri(request.uri()), e);
        }

        boolean accepted = false;
        for (int code : acceptedStatusCodes) {
            if (response.statusCode() == code) {
                accepted = true;
                break;
            }
        }
        if (!accepted) {
            throw new GitLabPublicationException(
                    "GitLab returned " + response.statusCode() + " for " + safeUri(request.uri())
                            + ": " + response.body());
        }

        try {
            return mapper.readTree(response.body());
        } catch (IOException e) {
            throw new GitLabPublicationException(
                    "GitLab's response for " + safeUri(request.uri()) + " was not valid JSON.", e);
        }
    }

    private URI uri(String path) {
        return URI.create(config.baseUrl() + "/api/v4/projects/" + encode(config.projectId()) + path);
    }

    /** The token never appears in a URI to begin with (it is a header), but strip query strings anyway. */
    private static String safeUri(URI uri) {
        return uri.getScheme() + "://" + uri.getAuthority() + uri.getPath();
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
