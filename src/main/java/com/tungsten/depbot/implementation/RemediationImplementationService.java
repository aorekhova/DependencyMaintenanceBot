package com.tungsten.depbot.implementation;

import com.tungsten.depbot.claude.ClaudeConfig;
import com.tungsten.depbot.claude.ClaudeInvoker;
import com.tungsten.depbot.claude.ClaudeOutputException;
import com.tungsten.depbot.claude.ClaudePhase;
import com.tungsten.depbot.claude.ClaudeResult;
import com.tungsten.depbot.claude.ClaudeResultExtractor;
import com.tungsten.depbot.claude.ClaudeRunOutcome;
import com.tungsten.depbot.claude.ClaudeRunRequest;
import com.tungsten.depbot.git.ChangeDisposition;
import com.tungsten.depbot.git.ChangeOutcome;
import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.git.RemediationChangeCommitter;
import com.tungsten.depbot.progress.RemediationProgressListener;
import com.tungsten.depbot.progress.RemediationStep;
import com.tungsten.depbot.run.RemediationRunService;
import com.tungsten.depbot.validation.FullBuildValidationGate;
import com.tungsten.depbot.validation.MavenBuildValidationGate;
import com.tungsten.depbot.validation.RemediationValidationGate;
import com.tungsten.depbot.validation.ValidationOutcome;
import com.tungsten.depbot.validation.ValidationRequest;
import com.tungsten.depbot.validation.ValidationStatus;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Phase two: hands the remediation to a developer, then decides whether to keep what they did.
 *
 * <p>Runs one Claude call on a branch the orchestrator already created and checked out, reads back the
 * report, and hands the result to {@link RemediationChangeCommitter}. The invoker below knows only about
 * processes; the branch above was created only after the assessment's ref was verified through git.
 *
 * <p><strong>Only a report that says the work was completed can lead to a commit.</strong> A failed call,
 * a timeout, an unreadable answer, an invalid report, or a deliberate stop on contradicted evidence all
 * mean the working tree goes back to the branch tip it started from -- including any partial edits made
 * before the agent realised it should stop. That is what lets the prompt promise, truthfully, that
 * stopping is safe and that nothing needs reverting by hand.
 *
 * <p><strong>Ending without a usable report is not, by itself, grounds to discard the work.</strong> That
 * covers more than {@link #ranOutOfInvestigationRoom running out of turns or time}: a primary call that
 * crashes outright, self-reports an error, or simply ends cleanly with an ordinary {@code end_turn} and
 * prose instead of the required JSON all reach the same place -- {@code report == null} after the primary
 * attempt. Whenever that happens, for whatever reason, a second, short, read-only call is attempted
 * before anything is rolled back: no further edits, just an honest report on whatever is already on the
 * branch (see {@link #finalizeImplementation}). If that report says the remediation is genuinely
 * finished, it is validated and committed exactly like any other {@code COMPLETED} report; if it says the
 * work is incomplete, {@code STOPPED_BLOCKED} with the reason is a correct, honest outcome, not a failure
 * -- and the working tree is undone exactly as it would be for any other stop. Only if the finalization
 * call itself also fails to produce a usable report does this end with nothing to act on at all -- and
 * even then, the orchestrator routes the group to the read-only Human Review Engineer rather than
 * simply discarding it; this class itself never retries the remediation a second time.
 *
 * <p>Every path writes {@code implementation-attempt.json} and the {@code patch.diff} that was produced,
 * kept even when rejected: a rolled-back diff is the most useful thing to look at afterwards and is gone
 * from the working tree by the time anyone could ask for it. {@code implementation-report.json} exists
 * only when there is a valid report, so its presence is itself the signal.
 *
 * <p><strong>A second, heavier gate runs after a commit is actually made.</strong> Once the
 * dependency-resolution gate has passed and the change is committed, a full {@code mvn -B package} is
 * run on the committed branch through {@link FullBuildValidationGate}. Unlike every other gate here, a
 * failure at this stage never undoes the commit -- it is purely diagnostic, resolving
 * "{@code COMMITTED_PENDING_VALIDATION}" into an actual pass or fail rather than leaving it open. This
 * runs unconditionally for every commit; there is no toggle, since it is exactly the check a developer
 * would run by hand before trusting the change, and skipping it silently would be worse than the time
 * it costs.
 */
public final class RemediationImplementationService {

    /** The validated report. Present only when one was actually produced. */
    public static final String REPORT_FILE = "implementation-report.json";

    /** The invocation record. Always present, whatever happened. */
    public static final String ATTEMPT_FILE = "implementation-attempt.json";

    /** The diff, kept whether it was committed or rolled back. */
    public static final String PATCH_FILE = "patch.diff";

    /** The local gate's verdict. Present whenever the gate was consulted. */
    public static final String VALIDATION_FILE = "validation.json";

    /** Maven's own output from the gate, so a refusal can be read rather than guessed at. */
    public static final String VALIDATION_OUTPUT_FILE = "validation-output.txt";

    /** The full-build gate's verdict. Present only when a commit actually happened. */
    public static final String FULL_BUILD_VALIDATION_FILE = "full-build-validation.json";

    /** The full build's own output, so a failure can be read rather than guessed at. */
    public static final String FULL_BUILD_OUTPUT_FILE = "full-build-output.txt";

    /** The plan-conformance gate's own verdict. Present only when an approved plan was in play. */
    public static final String PLAN_CONFORMANCE_FILE = "plan-conformance.json";

    /**
     * Where the finalization call's own {@code prompt.md}/{@code stdout.json} are written -- a
     * subdirectory of the attempt directory, never the attempt directory itself, so a finalization
     * attempt never overwrites the primary call's own artifacts.
     */
    static final String FINALIZATION_SUBDIRECTORY = "finalization";

    /**
     * The subtype Claude Code reports when a call ends because its turn budget ran out. Matched
     * exactly, and only against this one value -- an implementation that failed for any other reason
     * gets no finalization attempt, because there is nothing to report on: something is actually broken.
     */
    private static final String MAX_TURNS_SUBTYPE = "error_max_turns";

    private final ClaudeInvoker invoker;
    private final ClaudeConfig config;
    private final RemediationRunService runService;
    private final ImplementationPromptRenderer promptRenderer;
    private final ImplementationFinalizationPromptRenderer finalizationPromptRenderer;
    private final GitCommandRunner git;
    private final RemediationChangeCommitter committer;
    private final RemediationValidationGate validationGate;
    private final FullBuildValidationGate fullBuildGate;
    private final RemediationProgressListener progress;
    private final ImplementationReportParser parser;
    private final ClaudeResultExtractor resultExtractor;
    private final ImplementationJsonRenderer jsonRenderer;

    public RemediationImplementationService(
            ClaudeInvoker invoker,
            ClaudeConfig config,
            RemediationRunService runService,
            ImplementationPromptRenderer promptRenderer,
            GitCommandRunner git,
            RemediationChangeCommitter committer,
            RemediationValidationGate validationGate,
            FullBuildValidationGate fullBuildGate) {
        this(invoker, config, runService, promptRenderer, git, committer, validationGate, fullBuildGate,
                RemediationProgressListener.none());
    }

    public RemediationImplementationService(
            ClaudeInvoker invoker,
            ClaudeConfig config,
            RemediationRunService runService,
            ImplementationPromptRenderer promptRenderer,
            GitCommandRunner git,
            RemediationChangeCommitter committer,
            RemediationValidationGate validationGate,
            FullBuildValidationGate fullBuildGate,
            RemediationProgressListener progress) {
        this(invoker, config, runService, promptRenderer, new ImplementationFinalizationPromptRenderer(),
                git, committer, validationGate, fullBuildGate, progress,
                new ImplementationReportParser(), new ClaudeResultExtractor(),
                new ImplementationJsonRenderer());
    }

    RemediationImplementationService(
            ClaudeInvoker invoker,
            ClaudeConfig config,
            RemediationRunService runService,
            ImplementationPromptRenderer promptRenderer,
            ImplementationFinalizationPromptRenderer finalizationPromptRenderer,
            GitCommandRunner git,
            RemediationChangeCommitter committer,
            RemediationValidationGate validationGate,
            FullBuildValidationGate fullBuildGate,
            RemediationProgressListener progress,
            ImplementationReportParser parser,
            ClaudeResultExtractor resultExtractor,
            ImplementationJsonRenderer jsonRenderer) {
        this.progress = Objects.requireNonNull(progress, "progress");
        this.invoker = Objects.requireNonNull(invoker, "invoker");
        this.config = Objects.requireNonNull(config, "config");
        this.runService = Objects.requireNonNull(runService, "runService");
        this.promptRenderer = Objects.requireNonNull(promptRenderer, "promptRenderer");
        this.finalizationPromptRenderer =
                Objects.requireNonNull(finalizationPromptRenderer, "finalizationPromptRenderer");
        this.git = Objects.requireNonNull(git, "git");
        this.committer = Objects.requireNonNull(committer, "committer");
        this.validationGate = Objects.requireNonNull(validationGate, "validationGate");
        this.fullBuildGate = Objects.requireNonNull(fullBuildGate, "fullBuildGate");
        this.parser = Objects.requireNonNull(parser, "parser");
        this.resultExtractor = Objects.requireNonNull(resultExtractor, "resultExtractor");
        this.jsonRenderer = Objects.requireNonNull(jsonRenderer, "jsonRenderer");
    }

    /**
     * Where this unit's implementation artifacts belong for one specific attempt, without writing
     * anything -- {@code attempt-1} and {@code attempt-2} are always distinct directories, so a repair
     * attempt never overwrites the evidence its own initial attempt left behind.
     */
    public Path implementationDirectoryFor(String runId, String unitId, int attemptNumber) {
        return runService.unitDirectoryFor(runId, unitId)
                .resolve(ClaudePhase.IMPLEMENTATION.directoryName())
                .resolve("attempt-" + attemptNumber);
    }

    /**
     * @throws com.tungsten.depbot.git.GitCommandException if staging, committing or rolling back itself
     *                                                     fails -- at that point the checkout can no
     *                                                     longer be trusted to continue on its own
     */
    public ImplementationOutcome implement(ImplementationContext context) {
        Objects.requireNonNull(context, "context");

        Path directory = implementationDirectoryFor(context.runId(), context.unitId(), context.attemptNumber());
        ClaudeRunRequest request = ClaudeRunRequest.of(
                ClaudePhase.IMPLEMENTATION,
                context.workspace(),
                promptRenderer.render(context),
                directory,
                config);

        // Captured before Claude ever touches the workspace, so a rollback can later tell an untracked
        // path the attempt itself created apart from one that was already sitting there -- never removed
        // by this class's own cleanup, whatever it is (see RemediationChangeCommitter).
        List<String> baselineUntrackedFiles = git.listUntrackedFiles(context.workspace());

        progress.stepStarting(RemediationStep.IMPLEMENTATION, context.coordinates(),
                "on " + context.branchName() + "; Claude may edit whatever the fix needs");
        ClaudeRunOutcome primaryOutcome = invoker.run(request);
        ClaudeRunOutcome claudeOutcome = primaryOutcome;

        String primaryClaudeSubtype = resultExtractor.readSubtypeIfPresent(request.stdoutFile());
        boolean primaryMaxTurnsExceeded = MAX_TURNS_SUBTYPE.equals(primaryClaudeSubtype);

        ImplementationReport report = null;
        String primaryFailureReason = null;
        InvocationOutcomeReason primaryReason;

        if (primaryOutcome.timedOut()) {
            primaryFailureReason = describePrimaryRanOutOfRoom(primaryOutcome);
            primaryReason = InvocationOutcomeReason.PROCESS_TIMEOUT;
        } else if (primaryMaxTurnsExceeded) {
            primaryFailureReason = describePrimaryRanOutOfRoom(primaryOutcome);
            primaryReason = InvocationOutcomeReason.MAX_TURNS_EXCEEDED;
        } else if (!primaryOutcome.completedCleanly()) {
            primaryFailureReason = primaryOutcome.failureReason();
            primaryReason = InvocationOutcomeReason.NON_ZERO_EXIT;
        } else {
            try {
                ClaudeResult result = resultExtractor.extractFrom(request.stdoutFile());
                if (result.isError()) {
                    primaryFailureReason = "Claude reported an error result (subtype " + result.subtype()
                            + "), so its answer is not a completed implementation.";
                    primaryReason = InvocationOutcomeReason.NON_ZERO_EXIT;
                } else {
                    report = parser.parse(result.text());
                    primaryReason = InvocationOutcomeReason.COMPLETED;
                }
            } catch (ClaudeOutputException e) {
                primaryFailureReason = e.getMessage();
                primaryReason = InvocationOutcomeReason.MISSING_REPORT;
            } catch (ImplementationParseException e) {
                primaryFailureReason = e.getMessage();
                primaryReason = reasonFor(e.kind());
            }
        }

        InvocationRecord primaryInvocation = new InvocationRecord(
                primaryOutcome.command(), primaryOutcome.startedAt(), primaryOutcome.finishedAt(),
                primaryOutcome.exitCode(), primaryOutcome.timedOut(), primaryMaxTurnsExceeded,
                primaryClaudeSubtype, primaryReason, report != null);

        String failureReason = primaryFailureReason;
        boolean finalizationUsed = false;
        InvocationRecord finalizationInvocation = null;

        // Whatever the reason the primary call did not produce a usable report -- ran out of turns or
        // time, crashed outright, self-reported an error, or (just as real, and not any of the above)
        // ended cleanly with an ordinary end_turn and prose instead of the required JSON -- one short,
        // tool-free finalization call gets a chance to describe the actual state of the branch before
        // this unit is given up on. This is never a second remediation attempt: the finalization call has
        // no tools at all, and every fact it could have looked up has already been precomputed by Java
        // and embedded in its prompt (see finalizeImplementation).
        if (report == null) {
            ImplementationFinalizationResult finalization =
                    finalizeImplementation(context, request, directory, primaryFailureReason);
            report = finalization.report();
            claudeOutcome = finalization.claudeOutcome();
            failureReason = finalization.failureReason();
            finalizationInvocation = finalization.invocationRecord();
            finalizationUsed = true;
        }

        boolean workCompleted = report != null && report.workCompleted();
        progress.stepFinished(RemediationStep.IMPLEMENTATION, context.coordinates(),
                report == null ? "no usable report" : report.conclusion().name());

        // Plan conformance is Java-owned and structural, never a substitute for Implementation's own
        // STOPPED_PLAN_DEVIATION_REQUIRED self-report -- either signal alone is enough to treat this
        // attempt as a plan deviation. Phase A runs against the pre-commit working tree (nothing is
        // committed yet at this point) so an obviously non-conformant candidate never even reaches the
        // dependency-resolution gate, which would otherwise spend real Maven time on a doomed attempt.
        // Plan conformance has nothing to check for the partial-analysis fallback: that path never has a
        // structured plan (see ImplementationPromptRenderer's own constrained prompt for it) -- only raw
        // partial evidence and Mend's own data -- so there is no plannedChanges/affectedFiles set to
        // conform to. Likewise skipped whenever the group's own plannedChanges is empty (legacy/partial
        // analysis data, or a fixture that never populated it) -- there is nothing to check against.
        PlanConformanceGate.PhaseAResult phaseA = workCompleted && context.partialAnalysisState() == null
                && !context.group().plannedChanges().isEmpty()
                ? PlanConformanceGate.checkStructural(
                        git, context.workspace(), context.branchBaseSha(), context.group())
                : null;

        // The gate only has something to say about a change that claims to be a finished remediation.
        // Running it on a deliberate stop or a failed call would spend minutes to refuse work that is
        // being undone regardless. A Phase A violation skips it too -- there is no point resolving
        // dependencies for a candidate that has already deviated from its approved plan.
        ValidationRun validationRun = workCompleted && (phaseA == null || phaseA.result().conformant())
                ? validate(context, directory)
                : null;
        ValidationOutcome validation = validationRun == null ? null : validationRun.outcome();
        Map<String, String> resolvedVersionsByCoordinates =
                validationRun == null ? Map.of() : validationRun.resolvedVersionsByCoordinates();

        // Phase B: only once dependency validation has genuinely passed and Phase A left one or more
        // VERSION_BUMP entries it could not conclusively resolve from XML alone -- reuses that same
        // gate's already-computed per-coordinate resolved-version evidence, never a second Maven call.
        PlanConformanceResult planConformance = phaseA == null ? null : phaseA.result();
        if (phaseA != null && phaseA.result().conformant() && !phaseA.pendingVersionChecks().isEmpty()
                && validation != null && validation.status() == ValidationStatus.PASSED) {
            PlanConformanceResult phaseB = PlanConformanceGate.checkResolvedVersions(
                    phaseA.pendingVersionChecks(), resolvedVersionsByCoordinates);
            planConformance = PlanConformanceGate.merge(phaseA.result(), phaseB);
        }
        if (planConformance != null) {
            runService.writeAttemptFile(
                    directory.resolve(PLAN_CONFORMANCE_FILE), jsonRenderer.renderPlanConformance(planConformance));
        }

        // A plan-conformance failure refuses the commit exactly like a validation refusal does -- neither
        // Maven's own dependency-validation verdict (which may have genuinely PASSED, if Phase B is what
        // failed) nor its persisted validation.json is altered; this is a distinct, additional gate.
        String refusalReason;
        if (planConformance != null && !planConformance.conformant()) {
            refusalReason = "plan conformance check failed: " + String.join("; ", planConformance.violations());
        } else {
            refusalReason = validation == null || validation.permitsCommit() ? null : validation.reason();
        }

        progress.stepStarting(RemediationStep.COMMIT_DECISION, context.coordinates(), null);
        ChangeOutcome change = committer.finalizeChange(context.workspace(), context.branchName(),
                context.branchBaseSha(), workCompleted, refusalReason,
                commitMessage(context, report, resolvedVersionsByCoordinates), baselineUntrackedFiles);
        progress.stepFinished(RemediationStep.COMMIT_DECISION, context.coordinates(),
                change.disposition().name());

        runService.writeAttemptFile(directory.resolve(PATCH_FILE), change.patch());
        if (report != null) {
            runService.writeAttemptFile(directory.resolve(REPORT_FILE), jsonRenderer.render(report));
        }

        // The full build only has something to validate once a commit actually exists; running it on a
        // rolled-back or no-op attempt would spend tens of minutes checking a change that isn't there.
        ValidationOutcome fullBuildOutcome = change.committed()
                ? runFullBuildValidation(context, directory)
                : null;

        writeAttempt(context, claudeOutcome, directory, report, change, validation, fullBuildOutcome,
                failureReason, finalizationUsed, primaryInvocation, finalizationInvocation);

        return new ImplementationOutcome(context.runId(), context.unitId(), context.coordinates(),
                context.branchName(), report, change, validation, fullBuildOutcome, claudeOutcome,
                directory, failureReason, resolvedVersionsByCoordinates, planConformance);
    }

    /**
     * Runs a full {@code mvn -B package} on the branch as the implementation left it, after the commit
     * already stands. Never touches git: whatever this reports, the commit made earlier in this method
     * is not undone here. Runs once for the whole group, whatever its size -- a full build already
     * checks the entire reactor, so there is nothing member-specific for it to be told; the first
     * member's coordinates are passed only because {@link ValidationRequest} takes them, not because
     * this gate consults them.
     */
    private ValidationOutcome runFullBuildValidation(ImplementationContext context, Path directory) {
        String coordinates = context.coordinates();
        ImplementationGroupMember first = context.members().get(0);

        progress.stepStarting(RemediationStep.FULL_BUILD_VALIDATION, coordinates,
                "running mvn " + String.join(" ", MavenBuildValidationGate.BUILD_ARGS)
                        + " on the committed branch; this can take a long time");
        Runnable heartbeat = () -> progress.stepHeartbeat(
                RemediationStep.FULL_BUILD_VALIDATION, coordinates, null);

        ValidationOutcome outcome = fullBuildGate.validate(
                new ValidationRequest(context.workspace(), first.workItem().groupId(),
                        first.workItem().artifactId(), null),
                heartbeat);

        progress.stepFinished(RemediationStep.FULL_BUILD_VALIDATION, coordinates,
                outcome.status().name());

        runService.writeAttemptFile(
                directory.resolve(FULL_BUILD_VALIDATION_FILE), jsonRenderer.renderValidation(outcome));
        runService.writeAttemptFile(directory.resolve(FULL_BUILD_OUTPUT_FILE), outcome.output());
        return outcome;
    }

    /**
     * Runs the local gate against the working tree as the implementation left it, once per member of
     * the group, and records one aggregate verdict and one combined output before anything is staged.
     *
     * <p>The group's dependency-resolution validation passes only if every member's own check does --
     * a group exists precisely because its members were declared inseparable, so a fix that resolves
     * one finding while leaving another still vulnerable is not a passing outcome for the group.
     *
     * <p>The vulnerable version checked against each member is the one the group's own analysis actually
     * observed on the branch where it made an observation, and Mend's reported version otherwise -- the
     * analysis looked at the ref this branch came from, so its observation is the more reliable of the
     * two. {@code AnalysisRemediationGroup.observedVersion()} is a single, group-level field, though, so
     * it is only trustworthy as "the" vulnerable version for a singleton group -- for a multi-member
     * group it would broadcast one member's observed version onto every other member, each of which may
     * genuinely have started at a different version. A multi-member group therefore always falls back to
     * each member's own {@link com.tungsten.depbot.assessment.VulnerabilityWorkItem#reportedVersion()}.
     */
    private ValidationRun validate(ImplementationContext context, Path directory) {
        progress.stepStarting(RemediationStep.VALIDATION, context.coordinates(),
                "resolving the dependency tree offline for every finding in this group");

        List<ValidationOutcome> perMember = new ArrayList<>();
        Map<String, String> resolvedVersionsByCoordinates = new LinkedHashMap<>();
        for (ImplementationGroupMember member : context.members()) {
            String vulnerableVersion = context.isSingleMember() && context.group().observedVersion() != null
                    ? context.group().observedVersion()
                    : member.workItem().reportedVersion();
            ValidationOutcome outcome = validationGate.validate(new ValidationRequest(
                    context.workspace(), member.workItem().groupId(), member.workItem().artifactId(),
                    vulnerableVersion));
            perMember.add(outcome);
            if (outcome.resolvedVersion() != null) {
                resolvedVersionsByCoordinates.put(member.coordinates(), outcome.resolvedVersion());
            }
        }

        ValidationOutcome aggregate = aggregateValidation(context, perMember);
        progress.stepFinished(RemediationStep.VALIDATION, context.coordinates(), aggregate.status().name());

        runService.writeAttemptFile(
                directory.resolve(VALIDATION_FILE), jsonRenderer.renderValidation(aggregate));
        runService.writeAttemptFile(directory.resolve(VALIDATION_OUTPUT_FILE), aggregate.output());
        return new ValidationRun(aggregate, resolvedVersionsByCoordinates);
    }

    /**
     * The aggregate verdict every other caller in this class works with, plus the one thing the
     * aggregate itself cannot hold for a multi-member group: which version each individual member's own
     * gate call actually found it resolving to (see {@link ValidationOutcome#resolvedVersion()}). A
     * coordinate with no entry means its own resolved version was not reliably established.
     */
    private record ValidationRun(ValidationOutcome outcome, Map<String, String> resolvedVersionsByCoordinates) {
    }

    /** Combines every member's own gate verdict into one: the worst status wins, every reason is kept. */
    private static ValidationOutcome aggregateValidation(
            ImplementationContext context, List<ValidationOutcome> perMember) {
        if (perMember.size() == 1) {
            return perMember.get(0);
        }

        ValidationStatus worst = ValidationStatus.PASSED;
        List<String> command = new ArrayList<>();
        StringBuilder reason = new StringBuilder();
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < perMember.size(); i++) {
            String coordinates = context.members().get(i).coordinates();
            ValidationOutcome outcome = perMember.get(i);
            worst = worseOf(worst, outcome.status());
            if (!reason.isEmpty()) {
                reason.append(" | ");
            }
            reason.append(coordinates).append(": ").append(outcome.reason());
            output.append("=== ").append(coordinates).append(" ===\n").append(outcome.output()).append("\n\n");
            command.addAll(outcome.command());
        }
        // No single resolvedVersion is meaningful for a combined, multi-member verdict -- see
        // ValidationRun.resolvedVersionsByCoordinates for the per-member facts this collapses.
        return new ValidationOutcome(worst, reason.toString(), command, output.toString(), null);
    }

    private static ValidationStatus worseOf(ValidationStatus a, ValidationStatus b) {
        if (a == ValidationStatus.FAILED || b == ValidationStatus.FAILED) {
            return ValidationStatus.FAILED;
        }
        if (a == ValidationStatus.NOT_RUN || b == ValidationStatus.NOT_RUN) {
            return ValidationStatus.NOT_RUN;
        }
        return ValidationStatus.PASSED;
    }

    /**
     * Names every member and the version each one's own remediation actually landed on.
     *
     * <p>Three different things could answer "what version," in decreasing order of trust, and this
     * picks the first one actually available for each member:
     *
     * <ol>
     *   <li>{@code resolvedVersionsByCoordinates}: what {@link #validate}'s own dependency-resolution
     *       gate call for this exact member found it resolving to in the validated tree, after the
     *       change -- ground truth, not a plan. This is what the Remediation Engineer may have applied
     *       instead of the recommendation below, for a reason the gate has no opinion on; the commit
     *       title must describe what is actually there, not what was merely suggested beforehand.</li>
     *   <li>{@link com.tungsten.depbot.assessment.VulnerabilityWorkItem#botComputedTargetVersion()}: the
     *       per-member version Mend's own fix data suggested, computed long before grouping or
     *       implementation ever happened -- used only when the gate did not establish an actual version
     *       for this member (validation was skipped, inconclusive, or ambiguous).</li>
     *   <li>{@code AnalysisRemediationGroup.recommendedTargetVersion()}: one shared field for the whole
     *       group -- correct for a family that genuinely shares one version number (an
     *       httpcomponents5-style family), used only as the last resort for a member with neither of the
     *       above.</li>
     * </ol>
     *
     * <p>{@code resolvedVersionsByCoordinates} is deliberately never guessed at when the gate itself
     * could not name a single version (see {@link ValidationOutcome#resolvedVersion()}) -- an absent
     * entry falls through to the next, less authoritative source rather than inventing one.
     */
    private static String commitMessage(
            ImplementationContext context, ImplementationReport report,
            Map<String, String> resolvedVersionsByCoordinates) {
        String groupTarget = context.group().recommendedTargetVersion();
        String versions = context.members().stream()
                .map(member -> member.coordinates()
                        + targetSuffix(member, groupTarget, resolvedVersionsByCoordinates))
                .collect(Collectors.joining(", "));
        String subject = "remediate: " + versions;
        String body = report == null ? "" : "\n\n" + report.summary();
        return subject + " (unit " + context.unitId() + ")" + body;
    }

    private static String targetSuffix(
            ImplementationGroupMember member, String groupTarget,
            Map<String, String> resolvedVersionsByCoordinates) {
        String actual = resolvedVersionsByCoordinates.get(member.coordinates());
        String memberSuggested = member.workItem().botComputedTargetVersion();
        String target;
        if (actual != null && !actual.isBlank()) {
            target = actual;
        } else if (memberSuggested != null && !memberSuggested.isBlank()) {
            target = memberSuggested;
        } else {
            target = groupTarget;
        }
        return (target == null || target.isBlank()) ? "" : " -> " + target;
    }

    private void writeAttempt(
            ImplementationContext context,
            ClaudeRunOutcome claudeOutcome,
            Path directory,
            ImplementationReport report,
            ChangeOutcome change,
            ValidationOutcome validation,
            ValidationOutcome fullBuildOutcome,
            String failureReason,
            boolean finalizationUsed,
            InvocationRecord primaryInvocation,
            InvocationRecord finalizationInvocation) {

        ImplementationAttempt attempt = new ImplementationAttempt(
                context.runId(),
                context.unitId(),
                ClaudePhase.IMPLEMENTATION.name(),
                config.model(),
                context.coordinates(),
                context.branchName(),
                context.branchBaseSha(),
                context.verifiedSourceRef(),
                claudeOutcome.command(),
                claudeOutcome.startedAt(),
                claudeOutcome.finishedAt(),
                claudeOutcome.exitCode(),
                claudeOutcome.timedOut(),
                report != null,
                finalizationUsed,
                report == null ? null : report.conclusion(),
                change.disposition(),
                change.commitSha(),
                change.policyViolations(),
                validation == null ? null : validation.status(),
                validation == null ? null : validation.reason(),
                fullBuildOutcome == null ? null : fullBuildOutcome.status(),
                fullBuildOutcome == null ? null : fullBuildOutcome.reason(),
                describeDisposition(change, fullBuildOutcome),
                change.diagnosticDetail(),
                failureReason,
                primaryInvocation,
                finalizationInvocation);

        runService.writeAttemptFile(
                directory.resolve(ATTEMPT_FILE), jsonRenderer.renderAttempt(attempt));
    }

    /**
     * The disposition reason as it actually stands once everything {@code writeAttempt} already knows is
     * accounted for -- never the stale, commit-time-only sentence {@link ChangeOutcome#reason()} carries
     * for {@link ChangeDisposition#COMMITTED_PENDING_VALIDATION} (production
     * defect, pilot {@code 20260909-012226-8bfda1}: {@code implementation-attempt.json} still read
     * "nothing has compiled or tested it yet" next to an already-known {@code fullBuildStatus}, since the
     * full build always runs, synchronously, before this method is ever called for a committed change).
     *
     * <p>Every other disposition ({@code ROLLED_BACK}, {@code NO_CHANGES}) already carries a terminal,
     * accurate reason at the point {@link ChangeOutcome} is produced -- those are returned unchanged.
     */
    static String describeDisposition(ChangeOutcome change, ValidationOutcome fullBuildOutcome) {
        if (change.disposition() != ChangeDisposition.COMMITTED_PENDING_VALIDATION) {
            return change.reason();
        }
        if (fullBuildOutcome == null) {
            // Not reached via the current orchestration (the full build always runs before this method is
            // called for a committed change), but kept correct in isolation: nothing later than the commit
            // itself is known yet, so the original, still-accurate "pending" sentence is the honest answer.
            return change.reason();
        }
        return switch (fullBuildOutcome.status()) {
            case PASSED -> "Committed and successfully passed dependency validation and full build validation.";
            case FAILED -> "Committed and passed dependency validation, but the full build failed: "
                    + fullBuildOutcome.reason();
            case NOT_RUN -> "Committed and passed dependency validation, but the full build could not be "
                    + "run: " + fullBuildOutcome.reason();
        };
    }

    private static InvocationOutcomeReason reasonFor(ImplementationParseException.Kind kind) {
        return switch (kind) {
            case MISSING_REPORT -> InvocationOutcomeReason.MISSING_REPORT;
            case MALFORMED_REPORT -> InvocationOutcomeReason.MALFORMED_REPORT;
            case REPORT_VALIDATION_FAILED -> InvocationOutcomeReason.REPORT_VALIDATION_FAILED;
        };
    }

    /**
     * Whether the primary call ended specifically because it ran out of room to work, not because
     * anything actually went wrong: a wall-clock timeout (killed mid-run, nothing more it could have
     * done), or Claude Code's own {@value #MAX_TURNS_SUBTYPE} subtype, which it can report either with
     * a non-zero exit or, just as often, with a clean exit 0 -- {@code readSubtypeIfPresent} is checked
     * unconditionally so both shapes are caught the same way.
     */
    private boolean ranOutOfInvestigationRoom(ClaudeRunOutcome claudeOutcome, ClaudeRunRequest request) {
        if (claudeOutcome.timedOut()) {
            return true;
        }
        return MAX_TURNS_SUBTYPE.equals(resultExtractor.readSubtypeIfPresent(request.stdoutFile()));
    }

    /**
     * The short, read-only, report-only call that follows any primary call which did not end with a
     * usable report -- not only one that ran out of turns or time, but just as much one that crashed
     * outright, self-reported an error, or ended cleanly with an ordinary {@code end_turn} and prose
     * instead of the required JSON. Resumes the primary call's own session when Claude Code reported one
     * -- which a clean {@code end_turn} and {@value #MAX_TURNS_SUBTYPE} both ordinarily leave behind,
     * since Claude Code still writes a final document in both cases, just not one this class could use --
     * so the finalization call still has its own reasoning about the change in context. A wall-clock
     * timeout (or an outright crash before anything is written) leaves no session id to recover; the
     * finalization prompt then asks Claude to use its remaining read-only access to look at the branch
     * itself instead.
     *
     * <p>Writes its own {@code prompt.md}/{@code stdout.json} under {@link #FINALIZATION_SUBDIRECTORY},
     * never into the attempt directory itself, so the primary call's own artifacts are never overwritten.
     *
     * @param primaryFailureReason why the primary call did not already produce a usable report -- purely
     *                             descriptive, carried into the failure message if finalization also
     *                             does not produce one; {@code null} or blank is tolerated
     */
    private ImplementationFinalizationResult finalizeImplementation(
            ImplementationContext context,
            ClaudeRunRequest primaryRequest,
            Path directory,
            String primaryFailureReason) {

        String sessionId = resultExtractor.readSessionIdIfPresent(primaryRequest.stdoutFile());
        boolean resumingSameSession = sessionId != null;

        // Java gathers the actual evidence itself and hands it to Claude as prompt text -- the call
        // itself is tool-free (ClaudeToolPolicy.forImplementationFinalization()), so there is nothing
        // left for it to spend a turn discovering. branchBaseSha is this group's own accepted cumulative
        // starting point, never always S0, so the diff shown is only what this group itself attempted.
        String gitStatusShort = git.status(context.workspace());
        String gitDiff = git.diffAgainst(context.workspace(), context.branchBaseSha());
        String gitDiffStat = git.diffStatAgainst(context.workspace(), context.branchBaseSha());

        String finalizationPrompt = finalizationPromptRenderer.render(
                context, resumingSameSession, gitStatusShort, gitDiff, gitDiffStat);
        Path finalizationDirectory = directory.resolve(FINALIZATION_SUBDIRECTORY);

        ClaudeRunRequest finalizationRequest = ClaudeRunRequest.ofImplementationFinalization(
                context.workspace(), finalizationPrompt, finalizationDirectory, config, sessionId);

        ClaudeRunOutcome finalizationOutcome = invoker.run(finalizationRequest);
        String finalizationSubtype = resultExtractor.readSubtypeIfPresent(finalizationRequest.stdoutFile());
        boolean finalizationMaxTurnsExceeded = MAX_TURNS_SUBTYPE.equals(finalizationSubtype);

        ImplementationReport report = null;
        String failureReason = null;
        InvocationOutcomeReason reason;

        if (finalizationOutcome.timedOut()) {
            failureReason = describeFinalizationFailure(primaryFailureReason, "it did not finish within its timeout");
            reason = InvocationOutcomeReason.PROCESS_TIMEOUT;
        } else if (finalizationMaxTurnsExceeded) {
            failureReason = describeFinalizationFailure(primaryFailureReason,
                    "it ran out of turns (Claude reported subtype \"" + MAX_TURNS_SUBTYPE + "\")");
            reason = InvocationOutcomeReason.MAX_TURNS_EXCEEDED;
        } else if (!finalizationOutcome.completedCleanly()) {
            failureReason = describeFinalizationFailure(primaryFailureReason, finalizationOutcome.failureReason());
            reason = InvocationOutcomeReason.NON_ZERO_EXIT;
        } else {
            try {
                ClaudeResult result = resultExtractor.extractFrom(finalizationRequest.stdoutFile());
                if (result.isError()) {
                    failureReason = describeFinalizationFailure(primaryFailureReason,
                            "it reported an error result itself (subtype " + result.subtype() + ")");
                    reason = InvocationOutcomeReason.NON_ZERO_EXIT;
                } else {
                    report = parser.parse(result.text());
                    reason = InvocationOutcomeReason.COMPLETED;
                }
            } catch (ClaudeOutputException e) {
                failureReason = describeFinalizationFailure(primaryFailureReason, e.getMessage());
                reason = InvocationOutcomeReason.MISSING_REPORT;
            } catch (ImplementationParseException e) {
                failureReason = describeFinalizationFailure(primaryFailureReason, e.getMessage());
                reason = reasonFor(e.kind());
            }
        }

        InvocationRecord invocationRecord = new InvocationRecord(
                finalizationOutcome.command(), finalizationOutcome.startedAt(), finalizationOutcome.finishedAt(),
                finalizationOutcome.exitCode(), finalizationOutcome.timedOut(), finalizationMaxTurnsExceeded,
                finalizationSubtype, reason, report != null);

        return new ImplementationFinalizationResult(report, finalizationOutcome, failureReason, invocationRecord);
    }

    private static String describePrimaryRanOutOfRoom(ClaudeRunOutcome primaryOutcome) {
        return primaryOutcome.timedOut()
                ? "it did not finish within its timeout"
                : "it ran out of turns (Claude reported subtype \"" + MAX_TURNS_SUBTYPE + "\")";
    }

    private static String describeFinalizationFailure(String primaryFailureReason, String finalizationReason) {
        return "The implementation did not produce a usable report on its own"
                + (primaryFailureReason == null || primaryFailureReason.isBlank() ? "" : " (" + primaryFailureReason + ")")
                + ", and the report-only finalization attempt also did not produce a usable report: "
                + finalizationReason;
    }

    /**
     * What the finalization call produced: the report when there is a valid one, whichever outcome
     * should be treated as this attempt's own from here on -- the finalization call's, not the primary
     * call's, since it is the one that actually decided the outcome -- and this call's own, independently
     * classified {@link InvocationRecord} (see {@link ImplementationAttempt}).
     */
    private record ImplementationFinalizationResult(
            ImplementationReport report, ClaudeRunOutcome claudeOutcome, String failureReason,
            InvocationRecord invocationRecord) {
    }
}
