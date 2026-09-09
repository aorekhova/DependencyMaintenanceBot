package com.tungsten.depbot.git;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tungsten.depbot.remediation.LibraryRemediation;
import com.tungsten.depbot.remediation.PilotDependencySelector;
import com.tungsten.depbot.remediation.RemediationPlan;
import com.tungsten.depbot.remediation.RemediationSourceException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;

/**
 * Reads {@code reports/remediation-plan.json} and creates one branch per non-empty severity
 * group, all from the same {@code origin/master} commit -- and nothing else. No checkout is ever
 * switched here, so the repository's working tree is never touched: this is what makes the same
 * logic safe to reuse as both the standalone {@code prepare-remediation-branches} command and the
 * first stage of {@code remediate}.
 *
 * <p>Only {@code critical}, {@code high}, {@code medium} and {@code low} are ever considered.
 * {@code manualAnalysisRequired} is deliberately never touched -- those libraries need a human
 * decision before any branch is worth creating for them.
 *
 * <p>Every call to {@link #prepareBranches()} is one "run" and gets its own run id, included in
 * every branch name ({@code remediation/<runId>/<severity>}), so repeated runs never conflict.
 * Groups are attempted independently: a branch name collision on one severity fails only that
 * severity, the others are still attempted and reported.
 */
public final class RemediationBranchPreparationService {

    private static final List<String> GROUPS = List.of("critical", "high", "medium", "low");
    private static final String REMOTE = "origin";
    private static final String BASE_REF = "origin/master";
    private static final DateTimeFormatter RUN_ID_TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC);

    private final Path planPath;
    private final Supplier<GitWorktreeConfig> configSource;
    private final GitCommandRunner git;
    private final Supplier<String> runIdSupplier;
    private final JsonMapper mapper = JsonMapper.builder().build();

    public RemediationBranchPreparationService(
            Path planPath, Supplier<GitWorktreeConfig> configSource, GitCommandRunner git) {
        this(planPath, configSource, git, RemediationBranchPreparationService::generateRunId);
    }

    /**
     * @param runIdSupplier produces one fresh id per call; tests inject a fixed value so branch
     *                      names are predictable to assert on
     */
    public RemediationBranchPreparationService(
            Path planPath, Supplier<GitWorktreeConfig> configSource, GitCommandRunner git,
            Supplier<String> runIdSupplier) {
        this.planPath = Objects.requireNonNull(planPath, "planPath");
        this.configSource = Objects.requireNonNull(configSource, "configSource");
        this.git = Objects.requireNonNull(git, "git");
        this.runIdSupplier = Objects.requireNonNull(runIdSupplier, "runIdSupplier");
    }

    public RemediationBranchOutcome prepareBranches() {
        return prepareBranches(null, null);
    }

    /**
     * Same as {@link #prepareBranches()}, except the plan is first narrowed to exactly one library
     * (kept in its real severity bucket) via {@link PilotDependencySelector} -- a
     * {@code remediate --dependency} pilot run. {@code filterGroupId} and {@code filterArtifactId}
     * are both {@code null} for the unfiltered case; both must be non-null to filter.
     *
     * @throws com.tungsten.depbot.remediation.DependencyNotFoundException if the coordinates match
     *                                                                     no library that can become
     *                                                                     a remediation unit
     */
    public RemediationBranchOutcome prepareBranches(String filterGroupId, String filterArtifactId) {
        RemediationPlan plan = readPlan();
        if (filterGroupId != null) {
            plan = PilotDependencySelector.selectOnly(plan, filterGroupId, filterArtifactId);
        }
        String runId = runIdSupplier.get();
        Map<String, List<LibraryRemediation>> groups = groupsOf(plan);

        List<String> nonEmptyGroups = new ArrayList<>();
        List<String> emptyGroups = new ArrayList<>();
        for (String group : GROUPS) {
            (groups.get(group).isEmpty() ? emptyGroups : nonEmptyGroups).add(group);
        }

        if (nonEmptyGroups.isEmpty()) {
            return new RemediationBranchOutcome(plan, runId, null, List.of(), emptyGroups, List.of());
        }

        GitWorktreeConfig config = configSource.get();
        Path repoPath = config.repoPath();

        git.fetch(repoPath, REMOTE);
        String baseSha = git.revParse(repoPath, BASE_REF);

        List<CreatedBranch> created = new ArrayList<>();
        List<GroupFailure> failures = new ArrayList<>();
        for (String group : nonEmptyGroups) {
            String branchName = "remediation/" + runId + "/" + group;
            try {
                git.createBranch(repoPath, branchName, baseSha);
                created.add(new CreatedBranch(group, branchName));
            } catch (GitCommandException e) {
                failures.add(new GroupFailure(group, e.getMessage()));
            }
        }

        return new RemediationBranchOutcome(plan, runId, baseSha, created, emptyGroups, failures);
    }

    private static Map<String, List<LibraryRemediation>> groupsOf(RemediationPlan plan) {
        Map<String, List<LibraryRemediation>> groups = new LinkedHashMap<>();
        groups.put("critical", plan.critical());
        groups.put("high", plan.high());
        groups.put("medium", plan.medium());
        groups.put("low", plan.low());
        return groups;
    }

    /**
     * A timestamp plus a short random suffix: readable enough to tell runs apart at a glance, and
     * collision-resistant enough that two runs started in the same second still get distinct ids.
     * Digits and hyphens only, since colons (which {@link DateTimeFormatter#ISO_INSTANT} would
     * include) are not valid in a git branch name.
     */
    static String generateRunId() {
        String timestamp = RUN_ID_TIMESTAMP.format(Clock.systemUTC().instant());
        String randomSuffix = Long.toHexString(ThreadLocalRandom.current().nextLong() & 0xFFFFFFL);
        return timestamp + "-" + randomSuffix;
    }

    private RemediationPlan readPlan() {
        if (!Files.exists(planPath)) {
            throw new RemediationSourceException(
                    "Could not find " + planPath + ". Run \"plan-remediation\" first to produce it.");
        }
        String content;
        try {
            content = Files.readString(planPath, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RemediationSourceException("Could not read " + planPath, e);
        }
        try {
            return mapper.readValue(content, RemediationPlan.class);
        } catch (JsonProcessingException e) {
            throw new RemediationSourceException("Could not parse " + planPath + " as a remediation plan", e);
        }
    }
}
