package com.tungsten.depbot.run;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Renders one {@link RemediationUnit} as a self-contained Markdown task description.
 *
 * <p>The task is deliberately narrow: it names the one dependency to upgrade and states plainly
 * that nothing else is in scope. It does not itself launch or invoke any agent -- generating this
 * file and acting on it are two separate steps, and this application only ever does the former.
 */
public final class RemediationUnitTaskRenderer {

    public String render(RemediationUnit unit) {
        Objects.requireNonNull(unit, "unit");

        List<String> lines = new ArrayList<>();
        lines.add("# Remediation task: " + unit.coordinates());
        lines.add("");
        lines.add("- Run ID: " + unit.runId());
        lines.add("- Severity: " + unit.severity());
        lines.add("- Branch: " + unit.branch());
        lines.add("- Workspace path: " + unit.workspacePath());
        lines.add("- Current version: " + text(unit.currentVersion()));
        lines.add("- Target version: " + text(unit.targetVersion()));
        lines.add("- Status: " + unit.status());
        lines.add("- Attempts: " + unit.attempts());
        lines.add("");
        lines.add("## CVEs addressed");
        lines.add("");
        if (unit.vulnerabilityIds().isEmpty()) {
            lines.add("Not provided");
        } else {
            for (String vulnerabilityId : unit.vulnerabilityIds()) {
                lines.add("- " + vulnerabilityId);
            }
        }
        lines.add("");
        lines.add("## Instructions");
        lines.add("");
        lines.add("Work only on the branch listed above, inside the workspace path above. Do not switch "
                + "branches, stage, or commit anything yourself.");
        lines.add("");
        lines.add("### Environment and command rules");
        lines.add("");
        lines.add("- This process already runs with its working directory set to the workspace path "
                + "above; never run `cd` -- if you need to look elsewhere, use an absolute or relative "
                + "path in the command itself.");
        lines.add("- Never chain commands with `&&`, `;`, or `||`, and never use pipes (`|`) or output "
                + "redirection (`>`, `>>`, `<`). Each Bash command must be a single, standalone command, "
                + "issued as its own separate tool call.");
        lines.add("- Use the `Read`, `Glob` and `Grep` tools to look at files -- never `cat`, `find`, or "
                + "`ls` through Bash.");
        lines.add("- To check the current branch, run `git rev-parse --abbrev-ref HEAD`; `git branch` "
                + "is not available.");
        lines.add("");
        lines.add("### Checking whether `" + unit.coordinates() + "` is already present");
        lines.add("");
        lines.add("1. First search every `pom.xml` in this project for an exact `<groupId>" + unit.groupId()
                + "</groupId>` with `<artifactId>" + unit.artifactId() + "</artifactId>` declared directly.");
        lines.add("2. If no direct declaration is found, check whether it is already present "
                + "transitively by running Maven's dependency tree. Use the Maven Wrapper if this "
                + "project has one (`./mvnw` or `./mvnw.cmd`); otherwise use `mvn`. The only command "
                + "form allowed is:");
        lines.add("");
        lines.add("   ```");
        lines.add("   mvn -o -B dependency:tree -Dincludes=" + unit.coordinates());
        lines.add("   ```");
        lines.add("");
        lines.add("   (or the equivalent `./mvnw` / `./mvnw.cmd` form). Always keep `-o` (offline) and "
                + "`-B` (non-interactive). Never add `-DoutputFile`, and never run `compile`, `test`, "
                + "`package`, `install`, `deploy`, or any other Maven goal.");
        lines.add("3. If `dependency:tree` does not run successfully, do not conclude that the "
                + "dependency is absent. State plainly that whether it is present transitively could "
                + "not be confirmed.");
        lines.add("");
        lines.add("Upgrade `" + unit.coordinates() + "` from `" + text(unit.currentVersion()) + "` to `"
                + text(unit.targetVersion()) + "` in the build file(s) that declare it, making only the "
                + "code changes strictly required for the project to compile and its existing tests to "
                + "pass against the new version.");
        lines.add("");
        lines.add("### Allowed");
        lines.add("");
        lines.add("- Changing this dependency's declared version.");
        lines.add("- Changing code that directly breaks as a result of this specific version upgrade "
                + "(for example, an API signature the new version changed).");
        lines.add("");
        lines.add("### Forbidden");
        lines.add("");
        lines.add("- Renaming or moving any class, file, or package.");
        lines.add("- Any refactor broader than what this version upgrade strictly requires.");
        lines.add("- Deleting or disabling any existing test.");
        lines.add("- Skipping tests in any way (`skipTests`, `-DskipTests`, `@Disabled`, commenting out "
                + "test code, or anything equivalent).");
        lines.add("- Upgrading any other dependency not named in this task.");
        lines.add("");
        lines.add("This file only describes the task. Nothing in this repository starts work on it "
                + "automatically; a human or a separately launched agent decides when to act on it.");

        return String.join("\n", lines) + "\n";
    }

    private static String text(String value) {
        return (value == null || value.isBlank()) ? "Not provided" : value;
    }
}
