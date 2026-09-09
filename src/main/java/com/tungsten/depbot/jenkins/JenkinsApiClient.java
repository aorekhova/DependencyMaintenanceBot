package com.tungsten.depbot.jenkins;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Talks to the real Jenkins Remote API of an "old" (2.204.2) Jenkins installation over HTTPS/HTTP.
 *
 * <p>{@code JenkinsApiClientTest} runs entirely against a local {@code HttpServer} stub, which proves
 * this class builds the request exactly the way it intends to, never that a real Jenkins 2.204.2 accepts
 * it -- that confirmation only comes from an actual manual pilot run. The first such pilot against the
 * real {@code WebApplicationDependencyValidation} job caught exactly this class's own file-parameter bug
 * (see {@link #multipartBody} javadoc): {@code BASE_COMMIT_SHA}/{@code EXPECTED_TREE_SHA} arrived, the
 * build started, but {@code SOURCE_PATCH} never materialized in the workspace, because naming the
 * multipart part directly after the parameter is not how Jenkins core resolves a File Parameter's bytes.
 *
 * <p>{@code triggerBuild} posts to {@code job/<jobName>/build} -- the classic, version-appropriate
 * multipart endpoint for a parameterized build that includes a File Parameter -- never
 * {@code buildWithParameters}, which has no way to carry a file at all. This is specific to the already
 * manually-proven {@code WebApplicationDependencyValidation} job and its three existing parameters
 * ({@code SOURCE_PATCH} as a File Parameter, {@code BASE_COMMIT_SHA}/{@code EXPECTED_TREE_SHA} as string
 * parameters, all three described in the accompanying {@code json} field), not a general claim about
 * every Jenkins job or version.
 */
public final class JenkinsApiClient implements JenkinsClient {

    private static final String BOUNDARY = "----depbot-jenkins-boundary-7f3a9c";

    /** What a genuine Jenkins queue item path looks like -- {@code .../queue/item/<digits>/}. */
    private static final Pattern QUEUE_ITEM_PATH = Pattern.compile(".*/queue/item/\\d+/?");

    private final JenkinsConfig config;
    private final HttpClient httpClient;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public JenkinsApiClient(JenkinsConfig config) {
        this(config, HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build());
    }

    public JenkinsApiClient(JenkinsConfig config, HttpClient httpClient) {
        this.config = Objects.requireNonNull(config, "config");
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    }

    @Override
    public JenkinsBuildRef triggerBuild(JenkinsCandidate candidate) {
        Objects.requireNonNull(candidate, "candidate");

        // Captured strictly before the trigger request is sent -- this is the fallback identity anchor
        // if Jenkins answers with its known legacy (job-page) Location instead of a queue item; see
        // resolveTriggerOutcome and JenkinsBuildRef's own class javadoc.
        int nextBuildNumberBeforeTrigger = fetchNextBuildNumber();

        String[] crumb = fetchCrumbIfPresent();
        byte[] body = multipartBody(candidate);

        HttpRequest.Builder builder = HttpRequest.newBuilder(jobUri("build"))
                .header("Content-Type", "multipart/form-data; boundary=" + BOUNDARY)
                .header("Authorization", basicAuth())
                .timeout(Duration.ofSeconds(60))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        if (crumb != null) {
            builder.header(crumb[0], crumb[1]);
        }
        HttpRequest request = builder.build();

        HttpResponse<Void> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
        } catch (IOException e) {
            throw new JenkinsValidationException(
                    "Could not reach Jenkins to trigger " + config.jobName() + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new JenkinsValidationException("Interrupted while triggering " + config.jobName(), e);
        }

        if (response.statusCode() < 200 || response.statusCode() >= 400) {
            throw new JenkinsValidationException(
                    "Jenkins returned " + response.statusCode() + " when triggering " + config.jobName());
        }

        return resolveTriggerOutcome(request, response, candidate, nextBuildNumberBeforeTrigger);
    }

    /**
     * Reads the job's own {@code nextBuildNumber} -- the number the build Jenkins is about to create as
     * a result of the trigger about to be sent will get, or higher if something else races it. Read
     * strictly read-only, strictly before the trigger, so it can later anchor a legacy-fallback search to
     * "builds that did not exist yet when we triggered," never to a build any earlier, unrelated run left
     * behind.
     */
    private int fetchNextBuildNumber() {
        JsonNode job = tryGetJson(jobUri("api/json").toString());
        if (job == null || !job.hasNonNull("nextBuildNumber")) {
            throw new JenkinsValidationException(
                    "Could not read nextBuildNumber for " + config.jobName() + " before triggering -- "
                            + "refusing to trigger a build this client could not later identify.");
        }
        return job.path("nextBuildNumber").asInt();
    }

    /**
     * Decides, once, at trigger time, which of the two discovery modes {@link JenkinsBuildRef} supports
     * applies -- never re-decided later, and always from the trigger response's own {@code Location}
     * header, never from {@link HttpResponse#uri()} (which, with redirects disabled, is simply the
     * request's own URI echoed back -- the job's {@code /build} endpoint, not a queue item or the job
     * page) and never from the request URI directly. {@code Location} may legally be relative (per RFC
     * 7231 it always was, even though most servers send an absolute one); {@link URI#resolve(String)}
     * against the request's own URI handles both shapes safely, without ever substituting the
     * request/response URI for the header's own value.
     *
     * <ul>
     *   <li>Resolves to a genuine queue item ({@code .../queue/item/<digits>/}) -- the normal, documented
     *       shape -- {@link JenkinsBuildRef#queueItem} as before.</li>
     *   <li>Resolves to the job's own page -- Jenkins 2.204.2's confirmed, real behavior for a multipart
     *       trigger carrying a File Parameter, which is handled by its classic {@code doBuild} path
     *       rather than the queue-item REST path, even though the build is genuinely, successfully
     *       queued: {@link JenkinsBuildRef#legacyFallback}, anchored to {@code nextBuildNumberBeforeTrigger}
     *       and this candidate's own {@code BASE_COMMIT_SHA}/{@code EXPECTED_TREE_SHA} so {@link
     *       #waitForCompletion} can positively identify the resulting build later, rather than guessing.</li>
     *   <li>Anything else -- missing header, unresolvable value, or a Location that is neither of the
     *       above -- fails closed here, immediately, rather than being handed to {@link
     *       #waitForCompletion} to poll forever. This is exactly what an earlier version of this method
     *       did NOT do for the job-page case: it accepted that URL as if it were a queue item and polled
     *       it forever for an {@code executable} field a job page's own JSON never has, which from the
     *       outside looked exactly like this client hanging after Jenkins had already finished the real
     *       build.</li>
     * </ul>
     */
    private JenkinsBuildRef resolveTriggerOutcome(
            HttpRequest request, HttpResponse<Void> response, JenkinsCandidate candidate,
            int nextBuildNumberBeforeTrigger) {
        String locationHeader = response.headers().firstValue("Location").orElse(null);
        if (locationHeader == null || locationHeader.isBlank()) {
            throw new JenkinsValidationException(
                    "Jenkins accepted the trigger but returned no Location header at all, so there is no "
                            + "queue item or build to correlate.");
        }

        URI resolved;
        try {
            resolved = request.uri().resolve(locationHeader);
        } catch (IllegalArgumentException e) {
            throw new JenkinsValidationException(
                    "Jenkins accepted the trigger but its Location header (" + locationHeader
                            + ") could not be resolved to a usable URI: " + e.getMessage());
        }

        if (QUEUE_ITEM_PATH.matcher(resolved.getPath()).matches()) {
            return JenkinsBuildRef.queueItem(resolved.toString());
        }

        if (isSameJobUri(resolved)) {
            return JenkinsBuildRef.legacyFallback(
                    nextBuildNumberBeforeTrigger, candidate.baselineSha(), candidate.expectedTreeSha());
        }

        throw new JenkinsValidationException(
                "Jenkins accepted the trigger, but its Location header pointed neither at a queue item nor "
                        + "at the job itself (resolved to " + safeUri(resolved) + "); refusing to guess "
                        + "which build, if any, this trigger produced.");
    }

    /** Whether {@code uri} is exactly this job's own page -- the confirmed legacy-fallback Location shape. */
    private boolean isSameJobUri(URI uri) {
        String path = uri.getPath();
        if (path == null) {
            return false;
        }
        String jobPath = "/job/" + config.jobName() + "/";
        return path.equals(jobPath) || path.equals(jobPath.substring(0, jobPath.length() - 1));
    }

    @Override
    public JenkinsBuildResult waitForCompletion(
            JenkinsBuildRef ref, Duration timeout, Duration pollInterval, Runnable heartbeat) {
        Objects.requireNonNull(ref, "ref");
        Objects.requireNonNull(timeout, "timeout");
        Objects.requireNonNull(pollInterval, "pollInterval");

        long deadlineNanos = System.nanoTime() + timeout.toNanos();
        JenkinsBuildRef resolved = ref;

        while (resolved.buildNumber() == null) {
            if (System.nanoTime() >= deadlineNanos) {
                return timedOut(null, null);
            }
            try {
                resolved = resolved.isLegacyFallback() ? tryResolveLegacyBuild(resolved) : tryResolveQueueItem(resolved);
            } catch (AmbiguousBuildMatchException e) {
                return new JenkinsBuildResult(JenkinsValidationStatus.FAILED, null, null, null, e.getMessage());
            }
            if (resolved.buildNumber() == null) {
                sleep(pollInterval);
                runQuietly(heartbeat);
            }
        }

        while (true) {
            if (System.nanoTime() >= deadlineNanos) {
                return timedOut(resolved.buildNumber(), resolved.buildUrl());
            }
            JsonNode build = tryGetJson(resolved.buildUrl() + "api/json");
            if (build != null && !build.path("building").asBoolean(true)) {
                String result = build.path("result").asText(null);
                long durationMillis = build.path("duration").asLong(0);
                return new JenkinsBuildResult(statusOf(result), resolved.buildNumber(), resolved.buildUrl(),
                        durationMillis, "Jenkins reported result " + result);
            }
            sleep(pollInterval);
            runQuietly(heartbeat);
        }
    }

    private JenkinsBuildRef tryResolveQueueItem(JenkinsBuildRef ref) {
        JsonNode queueItem = tryGetJson(ref.queueItemUrl() + "api/json");
        if (queueItem == null) {
            return ref;
        }
        JsonNode executable = queueItem.get("executable");
        if (executable == null || executable.isNull()) {
            return ref;
        }
        return ref.withResolvedBuild(executable.path("number").asInt(), executable.path("url").asText());
    }

    /**
     * The legacy-fallback discovery path: since Jenkins never gave us a queue item to poll, the only way
     * to find our own build is to positively identify it among the job's own recent builds -- by number
     * (never older than {@code ref.legacyFallbackFromBuildNumber()}, captured before the trigger) AND by
     * its own {@code BASE_COMMIT_SHA}/{@code EXPECTED_TREE_SHA} build parameters matching this candidate's
     * exactly. A build number alone is never enough (a concurrent, unrelated trigger could easily land in
     * the same range); the parameter match is what makes this a positive identification rather than a
     * guess. Exactly one match resolves the build; zero matches leaves {@code ref} unchanged so the
     * caller keeps polling until its own timeout; more than one match is a genuine ambiguity this method
     * refuses to guess through -- surfaced to {@link #waitForCompletion} as {@link
     * AmbiguousBuildMatchException}, never as a silently-wrong pick.
     */
    private JenkinsBuildRef tryResolveLegacyBuild(JenkinsBuildRef ref) {
        JsonNode job = tryGetJson(jobUri("api/json").toString());
        if (job == null) {
            return ref;
        }

        List<JenkinsBuildRef> matches = new ArrayList<>();
        for (JsonNode buildRef : job.path("builds")) {
            int number = buildRef.path("number").asInt(-1);
            if (number < ref.legacyFallbackFromBuildNumber()) {
                continue;
            }
            String buildUrl = buildRef.path("url").asText(null);
            if (buildUrl == null || buildUrl.isBlank()) {
                continue;
            }
            JsonNode buildDetail = tryGetJson(buildUrl + "api/json");
            if (buildDetail == null) {
                continue;
            }
            if (buildParametersMatch(buildDetail, ref.legacyExpectedBaselineSha(), ref.legacyExpectedTreeSha())) {
                matches.add(ref.withResolvedBuild(number, buildUrl));
            }
        }

        if (matches.isEmpty()) {
            return ref;
        }
        if (matches.size() > 1) {
            throw new AmbiguousBuildMatchException(
                    "Found " + matches.size() + " builds of " + config.jobName() + " numbered >= "
                            + ref.legacyFallbackFromBuildNumber() + " whose BASE_COMMIT_SHA/EXPECTED_TREE_SHA "
                            + "build parameters all match this candidate -- cannot safely determine which one "
                            + "this trigger actually produced.");
        }
        return matches.get(0);
    }

    /** Whether {@code buildDetail}'s own build parameters carry exactly this candidate's identity. */
    private static boolean buildParametersMatch(JsonNode buildDetail, String expectedBaselineSha, String expectedTreeSha) {
        String actualBaselineSha = null;
        String actualTreeSha = null;
        for (JsonNode action : buildDetail.path("actions")) {
            for (JsonNode parameter : action.path("parameters")) {
                String name = parameter.path("name").asText("");
                if ("BASE_COMMIT_SHA".equals(name)) {
                    actualBaselineSha = parameter.path("value").asText(null);
                } else if ("EXPECTED_TREE_SHA".equals(name)) {
                    actualTreeSha = parameter.path("value").asText(null);
                }
            }
        }
        return expectedBaselineSha.equals(actualBaselineSha) && expectedTreeSha.equals(actualTreeSha);
    }

    /**
     * Internal control flow only -- never crosses {@link #waitForCompletion}'s own boundary. Caught there
     * and turned into a structured {@code FAILED} {@link JenkinsBuildResult}: a genuine ambiguity after a
     * trigger that Jenkins itself already accepted is a real, reportable validation fact, not an infra
     * failure to trigger the build at all (that is what {@code COULD_NOT_TRIGGER} means), and not a bug
     * in this class to let escape as an uncaught exception either.
     */
    private static final class AmbiguousBuildMatchException extends RuntimeException {
        AmbiguousBuildMatchException(String message) {
            super(message);
        }
    }

    private static JenkinsValidationStatus statusOf(String jenkinsResult) {
        if (jenkinsResult == null) {
            return JenkinsValidationStatus.FAILED;
        }
        return switch (jenkinsResult) {
            case "SUCCESS" -> JenkinsValidationStatus.SUCCESS;
            case "FAILURE" -> JenkinsValidationStatus.FAILED;
            case "ABORTED" -> JenkinsValidationStatus.ABORTED;
            case "UNSTABLE" -> JenkinsValidationStatus.UNSTABLE;
            default -> JenkinsValidationStatus.FAILED;
        };
    }

    private static JenkinsBuildResult timedOut(Integer buildNumber, String buildUrl) {
        return new JenkinsBuildResult(JenkinsValidationStatus.TIMED_OUT, buildNumber, buildUrl, null,
                "No definitive result arrived within the configured Jenkins build timeout.");
    }

    /** {@code null} if this Jenkins has no crumb issuer installed -- not every installation requires one. */
    private String[] fetchCrumbIfPresent() {
        HttpRequest request = HttpRequest.newBuilder(URI.create(config.baseUrl() + "/crumbIssuer/api/json"))
                .header("Authorization", basicAuth())
                .timeout(Duration.ofSeconds(30))
                .GET()
                .build();
        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new JenkinsValidationException("Could not reach Jenkins for a CSRF crumb: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new JenkinsValidationException("Interrupted while requesting a CSRF crumb", e);
        }
        if (response.statusCode() == 404) {
            return null;
        }
        if (response.statusCode() != 200) {
            throw new JenkinsValidationException("Jenkins returned " + response.statusCode() + " for a CSRF crumb.");
        }
        try {
            JsonNode json = mapper.readTree(response.body());
            return new String[] {json.path("crumbRequestField").asText("Jenkins-Crumb"), json.path("crumb").asText()};
        } catch (IOException e) {
            throw new JenkinsValidationException("Jenkins's crumb response was not valid JSON.", e);
        }
    }

    @Override
    public String fetchConsoleLog(int buildNumber) {
        HttpRequest request = HttpRequest.newBuilder(
                        URI.create(config.baseUrl() + "/job/" + config.jobName() + "/" + buildNumber + "/consoleText"))
                .header("Authorization", basicAuth())
                .timeout(Duration.ofSeconds(30))
                .GET()
                .build();
        try {
            HttpResponse<String> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return response.statusCode() == 200 ? response.body() : "";
        } catch (IOException | InterruptedException e) {
            // Not fatal -- a console log is best-effort evidence, never a condition this method fails on.
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return "";
        }
    }

    private JsonNode tryGetJson(String url) {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .header("Authorization", basicAuth())
                .timeout(Duration.ofSeconds(30))
                .GET()
                .build();
        try {
            HttpResponse<String> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() != 200) {
                return null;
            }
            return mapper.readTree(response.body());
        } catch (IOException | InterruptedException e) {
            // A single poll failing is not fatal -- waitForCompletion retries until the overall timeout.
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return null;
        }
    }

    /**
     * Jenkins's core File Parameter binding does not look for a multipart part literally named after the
     * parameter -- it looks up the {@code json} parameter definition's own {@code file} key, which names
     * the actual multipart field carrying the bytes. Naming the file part directly after the parameter
     * (e.g. {@code name="SOURCE_PATCH"}, no {@code file} key in the {@code json} entry) is silently
     * ignored by Jenkins 2.204.2: the trigger is accepted and a build starts, but the parameter is never
     * materialized in the workspace at all (confirmed against the real installation: {@code
     * BASE_COMMIT_SHA}/{@code EXPECTED_TREE_SHA} arrived correctly, but {@code $WORKSPACE/SOURCE_PATCH}
     * never existed). The documented, version-appropriate shape is the conventional
     * {@code file0}/{@code file1}/... multipart field name, referenced by the parameter's own
     * {@code "file": "file0"} entry -- {@code SOURCE_PATCH} itself is never renamed; it is still the
     * exact parameter name Jenkins materializes as {@code $WORKSPACE/SOURCE_PATCH}, which is what the
     * {@code "name"} key (not the multipart field name) actually controls.
     */
    private byte[] multipartBody(JenkinsCandidate candidate) {
        String parametersJson = "{\"parameter\": ["
                + "{\"name\": \"SOURCE_PATCH\", \"file\": \"file0\"}, "
                + "{\"name\": \"BASE_COMMIT_SHA\", \"value\": " + jsonString(candidate.baselineSha()) + "}, "
                + "{\"name\": \"EXPECTED_TREE_SHA\", \"value\": " + jsonString(candidate.expectedTreeSha()) + "}]}";

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeAscii(out, "--" + BOUNDARY + "\r\n");
        writeAscii(out, "Content-Disposition: form-data; name=\"file0\"; filename=\"SOURCE_PATCH\"\r\n");
        writeAscii(out, "Content-Type: application/octet-stream\r\n\r\n");
        writeUtf8(out, candidate.sourcePatch());
        writeAscii(out, "\r\n--" + BOUNDARY + "\r\n");
        writeAscii(out, "Content-Disposition: form-data; name=\"json\"\r\n\r\n");
        writeUtf8(out, parametersJson);
        writeAscii(out, "\r\n--" + BOUNDARY + "--\r\n");
        return out.toByteArray();
    }

    private static void writeAscii(ByteArrayOutputStream out, String value) {
        out.writeBytes(value.getBytes(StandardCharsets.US_ASCII));
    }

    private static void writeUtf8(ByteArrayOutputStream out, String value) {
        out.writeBytes(value.getBytes(StandardCharsets.UTF_8));
    }

    /** Strips any query string before a URL ever reaches an exception message, mirroring {@code GitLabApiClient}. */
    private static String safeUri(URI uri) {
        return uri.getScheme() + "://" + uri.getAuthority() + uri.getPath();
    }

    private static String jsonString(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private String basicAuth() {
        String credentials = config.username() + ":" + config.apiToken();
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    private URI jobUri(String action) {
        return URI.create(config.baseUrl() + "/job/" + config.jobName() + "/" + action);
    }

    private static void sleep(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void runQuietly(Runnable heartbeat) {
        if (heartbeat != null) {
            heartbeat.run();
        }
    }
}
