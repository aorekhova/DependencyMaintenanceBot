package com.tungsten.depbot.run;

import com.tungsten.depbot.git.CreatedBranch;
import com.tungsten.depbot.remediation.LibraryRemediation;
import com.tungsten.depbot.remediation.RemediationPlan;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds a {@link RunManifest} from a completed branch-preparation outcome: one {@link
 * RemediationUnit} per library in a severity group that actually got a branch.
 *
 * <p>Every unit gets the same {@code workspacePath} -- there is only one managed checkout for the
 * whole run, not one per severity. A severity group with libraries but no matching
 * {@link CreatedBranch} (which should not happen if this is only called after every group
 * succeeded or was empty) simply contributes no units for that group, rather than fabricating a
 * branch that does not exist.
 */
public final class RunManifestBuilder {

    private static final List<String> GROUPS = List.of("critical", "high", "medium", "low");

    private RunManifestBuilder() {
    }

    public static RunManifest build(
            Path runsRoot,
            String runId,
            String generatedAt,
            String baseCommitSha,
            RemediationPlan plan,
            List<CreatedBranch> created,
            String workspacePath) {

        Map<String, CreatedBranch> byGroup = new LinkedHashMap<>();
        for (CreatedBranch branch : created) {
            byGroup.put(branch.severity(), branch);
        }

        Map<String, List<LibraryRemediation>> librariesByGroup = new LinkedHashMap<>();
        librariesByGroup.put("critical", plan.critical());
        librariesByGroup.put("high", plan.high());
        librariesByGroup.put("medium", plan.medium());
        librariesByGroup.put("low", plan.low());

        List<RemediationUnit> units = new ArrayList<>();
        for (String group : GROUPS) {
            units.addAll(unitsFor(runsRoot, runId, group, librariesByGroup.get(group), byGroup.get(group), workspacePath));
        }

        // model stays null: no model has been used yet at branch-preparation time. The executor
        // stamps it when it actually runs.
        return new RunManifest(runId, generatedAt, RunManifest.CURRENT_VERSION, baseCommitSha,
                null, units, plan.manualAnalysisRequired(), plan.sourceSnapshotFingerprint());
    }

    private static List<RemediationUnit> unitsFor(
            Path runsRoot, String runId, String group, List<LibraryRemediation> libraries,
            CreatedBranch branch, String workspacePath) {
        if (libraries.isEmpty() || branch == null) {
            return List.of();
        }

        List<RemediationUnit> units = new ArrayList<>();
        for (LibraryRemediation library : libraries) {
            Path taskFile = RunPaths.taskFilePath(runsRoot, runId, group, library.groupId(), library.artifactId());
            units.add(new RemediationUnit(
                    runId,
                    RunPaths.unitId(group, library.groupId(), library.artifactId()),
                    library.maxSeverity(),
                    library.groupId(),
                    library.artifactId(),
                    library.currentVersion(),
                    library.targetVersion(),
                    library.vulnerabilityIds(),
                    branch.branchName(),
                    workspacePath,
                    taskFile.toString(),
                    RemediationUnit.PENDING_STATUS,
                    0));
        }
        return units;
    }
}
