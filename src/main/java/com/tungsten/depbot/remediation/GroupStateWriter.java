package com.tungsten.depbot.remediation;

import com.tungsten.depbot.run.RemediationRunService;

import java.nio.file.Files;
import java.time.Instant;
import java.util.Objects;

/**
 * Writes {@code units/<unitId>/group-state.json} -- always the FULL, current {@link GroupState} snapshot,
 * never an appended diff. Called from {@code VulnerabilityRemediationService} after every stage
 * transition {@code attemptGroup} actually reaches.
 *
 * <p>{@code unitId} is passed alongside the state rather than carried on {@link GroupState} itself, since
 * {@code GroupState} is an identity/audit record, not a filing-location one -- exactly the same separation
 * {@code RemediationRunService#unitDirectoryFor} already draws for every other per-unit artifact.
 */
public final class GroupStateWriter {

    static final String FILE_NAME = "group-state.json";

    private final RemediationRunService runService;
    private final GroupStateJsonRenderer renderer = new GroupStateJsonRenderer();
    private final GroupStateJsonReader reader = new GroupStateJsonReader();

    public GroupStateWriter(RemediationRunService runService) {
        this.runService = Objects.requireNonNull(runService, "runService");
    }

    public void write(String unitId, GroupState state) {
        Objects.requireNonNull(unitId, "unitId");
        Objects.requireNonNull(state, "state");
        var path = runService.unitDirectoryFor(state.runId(), unitId).resolve(FILE_NAME);
        runService.writeAttemptFile(path, renderer.render(state));
    }

    /**
     * Patches a group's own already-written {@code group-state.json} with a final outcome learned only
     * AFTER that group's own attempt already finished -- specifically, a cohort-level final-integration
     * Jenkins failure that blocks publication for every group in the cohort, even ones that were each
     * individually accepted. Reads the existing file back (never re-derives it), replaces only
     * {@code lastCompletedStage}/{@code updatedAt}/{@code finalOutcome}, and rewrites it in full -- every
     * planning-cycle/implementation-attempt history this group already recorded is preserved untouched.
     *
     * <p>Best-effort, exactly like {@link #write}: if the file was never written for this group (e.g. an
     * older run, or this audit trail failing to write earlier for some unrelated reason), there is nothing
     * to patch, and this is silently a no-op -- an audit trail must never fail the remediation itself.
     */
    public void markFinalOutcome(String runId, String unitId, GroupState.GroupFinalOutcome finalOutcome) {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(unitId, "unitId");
        Objects.requireNonNull(finalOutcome, "finalOutcome");
        var path = runService.unitDirectoryFor(runId, unitId).resolve(FILE_NAME);
        if (!Files.exists(path)) {
            return;
        }
        GroupState existing = reader.read(path);
        GroupState updated = new GroupState(
                existing.schemaVersion(), existing.runId(), existing.groupId(), existing.memberCoordinates(),
                existing.verifiedSourceRef(), existing.verifiedSourceSha(), existing.risky(),
                existing.automationSafety(), existing.automationSafetyReason(), existing.effectiveRiskReason(),
                GroupLifecycleStage.FINAL_OUTCOME_DECIDED, Instant.now().toString(),
                existing.implementationAttempts(),
                existing.applicablePatch(), finalOutcome, existing.publicationOutcome());
        write(unitId, updated);
    }
}
