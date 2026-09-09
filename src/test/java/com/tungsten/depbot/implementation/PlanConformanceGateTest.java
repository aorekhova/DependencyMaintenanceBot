package com.tungsten.depbot.implementation;

import com.tungsten.depbot.assessment.AnalysisRemediationGroup;
import com.tungsten.depbot.assessment.PlannedChangeType;
import com.tungsten.depbot.assessment.PlannedDependencyChange;
import com.tungsten.depbot.git.GitCommandRunner;
import com.tungsten.depbot.git.GitTestRepos;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fast regression tests for {@link PlanConformanceGate}'s two phases against real, temporary git
 * repositories and real POM XML content -- diff-parsing and XML-parsing are exactly the kind of logic
 * that is easy to get subtly wrong, so nothing here is mocked away.
 */
class PlanConformanceGateTest {

    @TempDir
    Path tempDir;

    private final GitCommandRunner git = new GitCommandRunner();

    private static final String BASELINE_POM = """
            <project>
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>app</artifactId>
              <version>1.0.0</version>
              <dependencies>
                <dependency>
                  <groupId>com.example</groupId>
                  <artifactId>artifact</artifactId>
                  <version>1.0</version>
                </dependency>
              </dependencies>
            </project>
            """;

    private String baselineSha(Path work) throws Exception {
        Files.writeString(work.resolve("pom.xml"), BASELINE_POM, StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "pom.xml");
        GitTestRepos.run(work, "git", "commit", "-q", "-m", "baseline pom");
        return git.currentHeadSha(work);
    }

    /** Writes and commits several files at once -- for multi-module fixtures where more than one pom.xml
     *  matters. Returns the resulting commit SHA. */
    private String commitFiles(Path work, Map<String, String> filesByRelativePath, String message) throws Exception {
        for (Map.Entry<String, String> entry : filesByRelativePath.entrySet()) {
            Path file = work.resolve(entry.getKey());
            if (file.getParent() != null) {
                Files.createDirectories(file.getParent());
            }
            Files.writeString(file, entry.getValue(), StandardCharsets.UTF_8);
            GitTestRepos.run(work, "git", "add", entry.getKey());
        }
        GitTestRepos.run(work, "git", "commit", "-q", "-m", message);
        return git.currentHeadSha(work);
    }

    private static AnalysisRemediationGroup planWith(List<String> affectedFiles, PlannedDependencyChange... changes) {
        return new AnalysisRemediationGroup(
                "g", List.of(), List.of(), "narrative", null, null, null, null, null, null, null,
                affectedFiles, null, null, null, null, List.of(), List.of(), List.of(changes));
    }

    private static AnalysisRemediationGroup planWith(PlannedDependencyChange... changes) {
        return planWith(List.of("pom.xml"), changes);
    }

    private static PlannedDependencyChange versionBump(String coordinates, String current, String target) {
        return new PlannedDependencyChange(coordinates, current, target, "pom.xml",
                PlannedChangeType.VERSION_BUMP, "closes the CVE by raising " + coordinates);
    }

    // ---- VERSION_BUMP: literal ------------------------------------------------------------------

    @Test
    @DisplayName("a literal version bump matching the plan is conformant")
    void literalVersionBumpMatchingPlanIsConformant() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);
        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("<version>1.0</version>", "<version>1.1</version>"),
                StandardCharsets.UTF_8);

        var phaseA = PlanConformanceGate.checkStructural(git, work, baseline,
                planWith(versionBump("com.example:artifact", "1.0", "1.1")));

        assertTrue(phaseA.result().conformant(), phaseA.result().violations().toString());
        assertTrue(phaseA.pendingVersionChecks().isEmpty());
    }

    @Test
    @DisplayName("a literal version bump mismatching the plan is flagged immediately by Phase A alone")
    void literalVersionBumpMismatchIsFlaggedByPhaseA() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);
        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("<version>1.0</version>", "<version>1.2</version>"),
                StandardCharsets.UTF_8);

        var phaseA = PlanConformanceGate.checkStructural(git, work, baseline,
                planWith(versionBump("com.example:artifact", "1.0", "1.1")));

        assertFalse(phaseA.result().conformant());
        assertTrue(phaseA.result().violations().get(0).contains("1.2"));
        assertTrue(phaseA.pendingVersionChecks().isEmpty(), "a literal mismatch is immediate, never deferred");
    }

    // ---- VERSION_BUMP: property-based ------------------------------------------------------------

    private static final String PROPERTY_BASED_POM = """
            <project>
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>app</artifactId>
              <version>1.0.0</version>
              <properties>
                <lib.version>1.0</lib.version>
              </properties>
              <dependencies>
                <dependency>
                  <groupId>com.example</groupId>
                  <artifactId>artifact</artifactId>
                  <version>${lib.version}</version>
                </dependency>
              </dependencies>
            </project>
            """;

    @Test
    @DisplayName("a Maven property-based version, defined in the same POM, is resolved directly by Phase A "
            + "-- never deferred to Phase B when the local file alone already proves it")
    void propertyBasedVersionResolvedDirectlyByPhaseA() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve("pom.xml"), PROPERTY_BASED_POM, StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "pom.xml");
        GitTestRepos.run(work, "git", "commit", "-q", "-m", "baseline pom");
        String baseline = git.currentHeadSha(work);

        Files.writeString(work.resolve("pom.xml"),
                PROPERTY_BASED_POM.replace("<lib.version>1.0</lib.version>", "<lib.version>1.1</lib.version>"),
                StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(versionBump("com.example:artifact", "1.0", "1.1"));
        var phaseA = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertTrue(phaseA.result().conformant(), phaseA.result().violations().toString());
        assertTrue(phaseA.pendingVersionChecks().isEmpty(),
                "the property is defined in the same, locally-known POM -- Phase A resolves it itself");
    }

    @Test
    @DisplayName("a property-based version that resolves to something other than the plan's target is a "
            + "violation, not a deferral")
    void propertyBasedVersionMismatchIsFlaggedByPhaseA() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve("pom.xml"), PROPERTY_BASED_POM, StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "pom.xml");
        GitTestRepos.run(work, "git", "commit", "-q", "-m", "baseline pom");
        String baseline = git.currentHeadSha(work);

        Files.writeString(work.resolve("pom.xml"),
                PROPERTY_BASED_POM.replace("<lib.version>1.0</lib.version>", "<lib.version>1.0.9</lib.version>"),
                StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(versionBump("com.example:artifact", "1.0", "1.1"));
        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertFalse(result.result().conformant());
        assertTrue(result.result().violations().get(0).contains("1.0.9"));
    }

    // ---- VERSION_BUMP: dependencyManagement/BOM-inherited ------------------------------------------

    private static final String INHERITED_VERSION_POM = """
            <project>
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>app</artifactId>
              <version>1.0.0</version>
              <dependencyManagement>
                <dependencies>
                  <dependency>
                    <groupId>com.example</groupId>
                    <artifactId>artifact</artifactId>
                    <version>1.0</version>
                  </dependency>
                </dependencies>
              </dependencyManagement>
              <dependencies>
                <dependency>
                  <groupId>com.example</groupId>
                  <artifactId>artifact</artifactId>
                </dependency>
              </dependencies>
            </project>
            """;

    @Test
    @DisplayName("a dependencyManagement-inherited version (no explicit <version> at the declaration site), "
            + "in the same POM, is resolved directly by Phase A -- never deferred")
    void dependencyManagementInheritedVersionResolvedDirectlyByPhaseA() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve("pom.xml"), INHERITED_VERSION_POM, StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "pom.xml");
        GitTestRepos.run(work, "git", "commit", "-q", "-m", "baseline pom");
        String baseline = git.currentHeadSha(work);

        Files.writeString(work.resolve("pom.xml"),
                INHERITED_VERSION_POM.replaceFirst("<version>1.0</version>", "<version>1.1</version>"),
                StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(versionBump("com.example:artifact", "1.0", "1.1"));
        var phaseA = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertTrue(phaseA.result().conformant(), phaseA.result().violations().toString());
        assertTrue(phaseA.pendingVersionChecks().isEmpty(),
                "the dependencyManagement entry is in the same, locally-known POM -- Phase A resolves it itself");
    }

    // ---- DEPENDENCY_MANAGEMENT_ADDITION -------------------------------------------------------------

    @Test
    @DisplayName("DEPENDENCY_MANAGEMENT_ADDITION is conformant only when the exact entry exists")
    void dependencyManagementAdditionConformantOnlyWhenEntryExists() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);

        PlannedDependencyChange planned = new PlannedDependencyChange(
                "com.example:other-lib", null, "2.0", "pom.xml",
                PlannedChangeType.DEPENDENCY_MANAGEMENT_ADDITION, "pin a transitive dependency");
        AnalysisRemediationGroup plan = planWith(planned);

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("</project>", """
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>com.example</groupId>
                        <artifactId>other-lib</artifactId>
                        <version>2.0</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """), StandardCharsets.UTF_8);
        assertTrue(PlanConformanceGate.checkStructural(git, work, baseline, plan).result().conformant());
    }

    @Test
    @DisplayName("DEPENDENCY_MANAGEMENT_ADDITION is flagged when the entry is absent")
    void dependencyManagementAdditionFlaggedWhenAbsent() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);

        PlannedDependencyChange planned = new PlannedDependencyChange(
                "com.example:other-lib", null, "2.0", "pom.xml",
                PlannedChangeType.DEPENDENCY_MANAGEMENT_ADDITION, "pin a transitive dependency");
        AnalysisRemediationGroup plan = planWith(planned);

        // no dependencyManagement entry added at all, but touch the file so it's in scope
        Files.writeString(work.resolve("pom.xml"), BASELINE_POM + "<!-- touched -->", StandardCharsets.UTF_8);

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);
        assertFalse(result.result().conformant());
        assertTrue(result.result().violations().get(0).contains("other-lib"));
    }

    @Test
    @DisplayName("DEPENDENCY_MANAGEMENT_ADDITION is a no-op violation when the baseline already had the "
            + "planned target version -- not a false CONFORMS")
    void dependencyManagementAdditionNoOpAtBaselineIsViolation() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String managedEntry = """
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>com.example</groupId>
                        <artifactId>other-lib</artifactId>
                        <version>2.0</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """;
        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("</project>", managedEntry),
                StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "pom.xml");
        GitTestRepos.run(work, "git", "commit", "-q", "-m", "baseline pom");
        String baseline = git.currentHeadSha(work);

        // Implementation touches the file, but the management entry itself was already at 2.0.
        Files.writeString(work.resolve("pom.xml"),
                BASELINE_POM.replace("</project>", managedEntry) + "<!-- touched, no relevant change -->",
                StandardCharsets.UTF_8);

        PlannedDependencyChange planned = new PlannedDependencyChange(
                "com.example:other-lib", null, "2.0", "pom.xml",
                PlannedChangeType.DEPENDENCY_MANAGEMENT_ADDITION, "pin a transitive dependency");
        var result = PlanConformanceGate.checkStructural(git, work, baseline, planWith(planned));

        assertFalse(result.result().conformant());
        assertTrue(result.result().violations().get(0).contains("already present at the baseline"),
                result.result().violations().toString());
    }

    @Test
    @DisplayName("DEPENDENCY_MANAGEMENT_ADDITION is conformant when the entry's version genuinely changed "
            + "from a different baseline value to the planned target")
    void dependencyManagementAdditionGenuineVersionChangeFromBaselineConforms() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        java.util.function.Function<String, String> managedEntryWith = (String version) -> """
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>com.example</groupId>
                        <artifactId>other-lib</artifactId>
                        <version>%s</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """.formatted(version);
        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("</project>", managedEntryWith.apply("1.0")),
                StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "pom.xml");
        GitTestRepos.run(work, "git", "commit", "-q", "-m", "baseline pom");
        String baseline = git.currentHeadSha(work);

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("</project>", managedEntryWith.apply("2.0")),
                StandardCharsets.UTF_8);

        PlannedDependencyChange planned = new PlannedDependencyChange(
                "com.example:other-lib", "1.0", "2.0", "pom.xml",
                PlannedChangeType.DEPENDENCY_MANAGEMENT_ADDITION, "raise the pinned version");
        var result = PlanConformanceGate.checkStructural(git, work, baseline, planWith(planned));

        assertTrue(result.result().conformant(), result.result().violations().toString());
    }

    @Test
    @DisplayName("a literal imported BOM version edit is conformant")
    void literalImportedBomVersionEditIsConformant() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        java.util.function.Function<String, String> bomImportWith = version -> BASELINE_POM.replace(
                "</project>", """
                          <dependencyManagement>
                            <dependencies>
                              <dependency>
                                <groupId>com.fasterxml.jackson</groupId>
                                <artifactId>jackson-bom</artifactId>
                                <version>%s</version>
                                <type>pom</type>
                                <scope>import</scope>
                              </dependency>
                            </dependencies>
                          </dependencyManagement>
                        </project>
                        """.formatted(version));
        Files.writeString(work.resolve("pom.xml"), bomImportWith.apply("2.22.1"), StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "pom.xml");
        GitTestRepos.run(work, "git", "commit", "-q", "-m", "baseline pom");
        String baseline = git.currentHeadSha(work);

        Files.writeString(work.resolve("pom.xml"), bomImportWith.apply("2.22.2"), StandardCharsets.UTF_8);

        PlannedDependencyChange planned = new PlannedDependencyChange(
                "com.fasterxml.jackson:jackson-bom", "2.22.1", "2.22.2", "pom.xml",
                PlannedChangeType.DEPENDENCY_MANAGEMENT_ADDITION, "raise the imported BOM's own version");
        var result = PlanConformanceGate.checkStructural(git, work, baseline, planWith(planned));

        assertTrue(result.result().conformant(), result.result().violations().toString());
    }

    @Test
    @DisplayName("a property-backed imported BOM version is conformant when only the property changes")
    void propertyBackedImportedBomVersionIsConformant() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String bomWithPropertyVersion = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>app</artifactId>
                  <version>1.0.0</version>
                  <properties>
                    <jackson2.version>2.22.1</jackson2.version>
                  </properties>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>com.fasterxml.jackson</groupId>
                        <artifactId>jackson-bom</artifactId>
                        <version>${jackson2.version}</version>
                        <type>pom</type>
                        <scope>import</scope>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """;
        Files.writeString(work.resolve("pom.xml"), bomWithPropertyVersion, StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "pom.xml");
        GitTestRepos.run(work, "git", "commit", "-q", "-m", "baseline pom");
        String baseline = git.currentHeadSha(work);

        Files.writeString(work.resolve("pom.xml"),
                bomWithPropertyVersion.replace("<jackson2.version>2.22.1</jackson2.version>",
                        "<jackson2.version>2.22.2</jackson2.version>"),
                StandardCharsets.UTF_8);

        PlannedDependencyChange planned = new PlannedDependencyChange(
                "com.fasterxml.jackson:jackson-bom", "2.22.1", "2.22.2", "pom.xml",
                PlannedChangeType.DEPENDENCY_MANAGEMENT_ADDITION, "raise the imported BOM's own version");
        var result = PlanConformanceGate.checkStructural(git, work, baseline, planWith(planned));

        assertTrue(result.result().conformant(), result.result().violations().toString());
    }

    // ---- VERSION_BUMP against an existing dependencyManagement/BOM entry, no direct consumer ---------
    //
    // Production defect (pilot 20260908-220923-771c06): Claude #1 correctly classified an existing
    // imported BOM's own version raise as VERSION_BUMP (per its own contract: an entry that already
    // existed at baseline and only changed version is a VERSION_BUMP, not a DEPENDENCY_MANAGEMENT_ADDITION),
    // but checkVersionBump's discovery only ever looked for a direct <dependency> -- a BOM import (or any
    // dependencyManagement-only entry nothing consumes directly yet) has no such thing, so it was rejected
    // as "found nowhere" even though the entry, and the exact version bump, were both genuinely there.

    private static String bomImportPom(String version) {
        return BASELINE_POM.replace("</project>", """
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>com.fasterxml.jackson</groupId>
                        <artifactId>jackson-bom</artifactId>
                        <version>%s</version>
                        <type>pom</type>
                        <scope>import</scope>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """.formatted(version));
    }

    @Test
    @DisplayName("VERSION_BUMP of an existing imported BOM entry with a literal version, no direct consumer "
            + "anywhere, is conformant")
    void versionBumpOfExistingImportedBomEntryIsConformant() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve("pom.xml"), bomImportPom("2.22.1"), StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "pom.xml");
        GitTestRepos.run(work, "git", "commit", "-q", "-m", "baseline pom");
        String baseline = git.currentHeadSha(work);

        Files.writeString(work.resolve("pom.xml"), bomImportPom("2.22.2"), StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(
                versionBump("com.fasterxml.jackson:jackson-bom", "2.22.1", "2.22.2"));
        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertTrue(result.result().conformant(), result.result().violations().toString());
        assertTrue(result.pendingVersionChecks().isEmpty());
    }

    @Test
    @DisplayName("VERSION_BUMP of an existing imported BOM entry that never actually changed is a no-op "
            + "violation")
    void versionBumpOfUnchangedImportedBomEntryIsNoOpViolation() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve("pom.xml"), bomImportPom("2.22.2"), StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "pom.xml");
        GitTestRepos.run(work, "git", "commit", "-q", "-m", "baseline pom");
        String baseline = git.currentHeadSha(work);

        // Implementation touches the file, but the BOM's own version was already 2.22.2 at baseline too.
        Files.writeString(work.resolve("pom.xml"), bomImportPom("2.22.2") + "<!-- touched, no relevant change -->",
                StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(
                versionBump("com.fasterxml.jackson:jackson-bom", "2.22.1", "2.22.2"));
        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertFalse(result.result().conformant());
        assertTrue(result.result().violations().get(0).contains("already present at the baseline"),
                result.result().violations().toString());
    }

    @Test
    @DisplayName("VERSION_BUMP of an existing imported BOM entry that resolves to something other than the "
            + "plan's target is a violation")
    void versionBumpOfImportedBomEntryWrongTargetIsViolation() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        Files.writeString(work.resolve("pom.xml"), bomImportPom("2.22.1"), StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "pom.xml");
        GitTestRepos.run(work, "git", "commit", "-q", "-m", "baseline pom");
        String baseline = git.currentHeadSha(work);

        Files.writeString(work.resolve("pom.xml"), bomImportPom("2.22.9"), StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(
                versionBump("com.fasterxml.jackson:jackson-bom", "2.22.1", "2.22.2"));
        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertFalse(result.result().conformant());
        assertTrue(result.result().violations().get(0).contains("2.22.9"), result.result().violations().toString());
    }

    @Test
    @DisplayName("VERSION_BUMP of an existing, non-BOM dependencyManagement entry with no direct consumer "
            + "anywhere is conformant")
    void versionBumpOfExistingNonBomManagementEntryIsConformant() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        java.util.function.Function<String, String> managementEntryWith = version -> BASELINE_POM.replace(
                "</project>", """
                          <dependencyManagement>
                            <dependencies>
                              <dependency>
                                <groupId>com.example</groupId>
                                <artifactId>other-lib</artifactId>
                                <version>%s</version>
                              </dependency>
                            </dependencies>
                          </dependencyManagement>
                        </project>
                        """.formatted(version));
        Files.writeString(work.resolve("pom.xml"), managementEntryWith.apply("2.0"), StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "pom.xml");
        GitTestRepos.run(work, "git", "commit", "-q", "-m", "baseline pom");
        String baseline = git.currentHeadSha(work);

        Files.writeString(work.resolve("pom.xml"), managementEntryWith.apply("3.0"), StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(versionBump("com.example:other-lib", "2.0", "3.0"));
        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertTrue(result.result().conformant(), result.result().violations().toString());
    }

    @Test
    @DisplayName("VERSION_BUMP against a dependencyManagement/BOM entry that did not exist at the baseline "
            + "at all fails closed -- a newly added entry is a DEPENDENCY_MANAGEMENT_ADDITION, never "
            + "silently accepted as a version bump of an existing one")
    void versionBumpAgainstManagementEntryAbsentAtBaselineFailsClosed() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);

        // The BOM import did not exist at baseline at all -- this attempt added it outright.
        Files.writeString(work.resolve("pom.xml"), bomImportPom("2.22.2"), StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(
                versionBump("com.fasterxml.jackson:jackson-bom", "2.22.1", "2.22.2"));
        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertFalse(result.result().conformant());
        assertTrue(result.result().violations().get(0).contains("DEPENDENCY_MANAGEMENT_ADDITION"),
                result.result().violations().toString());
    }

    @Test
    @DisplayName("VERSION_BUMP of an existing imported BOM entry whose version property is inherited from "
            + "a local parent POM resolves correctly")
    void versionBumpOfImportedBomEntryWithParentInheritedPropertyResolvesCorrectly() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String parentWithProperty = parentPom("parent", "2.22.1");
        String childWithBomImport = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <parent>
                    <groupId>com.example</groupId>
                    <artifactId>parent</artifactId>
                    <version>1.0.0</version>
                    <relativePath>../parent/pom.xml</relativePath>
                  </parent>
                  <artifactId>child</artifactId>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>com.fasterxml.jackson</groupId>
                        <artifactId>jackson-bom</artifactId>
                        <version>${lib.version}</version>
                        <type>pom</type>
                        <scope>import</scope>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """;
        String baseline = commitFiles(work,
                Map.of("parent/pom.xml", parentWithProperty, "child/pom.xml", childWithBomImport), "baseline");

        // Only the parent's own property changes; child/pom.xml is never rewritten again.
        Files.writeString(work.resolve("parent/pom.xml"), parentPom("parent", "2.22.2"), StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(
                List.of("parent/pom.xml"), versionBump("com.fasterxml.jackson:jackson-bom", "2.22.1", "2.22.2"));
        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertTrue(result.result().conformant(), result.result().violations().toString());
    }

    @Test
    @DisplayName("production regression: an existing imported jackson-bom entry, version driven by a "
            + "property in the same POM, bumped 2.22.1 -> 2.22.2 and classified VERSION_BUMP is conformant "
            + "(pilot 20260908-220923-771c06)")
    void productionJacksonBomVersionBumpRegressionIsConformant() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String bomWithPropertyVersion = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>app</artifactId>
                  <version>1.0.0</version>
                  <properties>
                    <jackson2.version>2.22.1</jackson2.version>
                  </properties>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>com.fasterxml.jackson</groupId>
                        <artifactId>jackson-bom</artifactId>
                        <version>${jackson2.version}</version>
                        <type>pom</type>
                        <scope>import</scope>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """;
        Files.writeString(work.resolve("pom.xml"), bomWithPropertyVersion, StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "pom.xml");
        GitTestRepos.run(work, "git", "commit", "-q", "-m", "baseline pom");
        String baseline = git.currentHeadSha(work);

        Files.writeString(work.resolve("pom.xml"),
                bomWithPropertyVersion.replace("<jackson2.version>2.22.1</jackson2.version>",
                        "<jackson2.version>2.22.2</jackson2.version>"),
                StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(
                versionBump("com.fasterxml.jackson:jackson-bom", "2.22.1", "2.22.2"));
        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertTrue(result.result().conformant(), result.result().violations().toString());
        assertTrue(result.pendingVersionChecks().isEmpty());
    }

    // ---- EXCLUSION_ADDED ------------------------------------------------------------------------------

    @Test
    @DisplayName("EXCLUSION_ADDED is conformant only when the exact exclusion exists")
    void exclusionAddedConformantOnlyWhenExclusionExists() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);

        PlannedDependencyChange planned = new PlannedDependencyChange(
                "com.example:transitive-bad", null, null, "pom.xml",
                PlannedChangeType.EXCLUSION_ADDED, "exclude a vulnerable transitive dependency");
        AnalysisRemediationGroup plan = planWith(planned);

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("</dependency>", """
                    <exclusions>
                      <exclusion>
                        <groupId>com.example</groupId>
                        <artifactId>transitive-bad</artifactId>
                      </exclusion>
                    </exclusions>
                  </dependency>
                """), StandardCharsets.UTF_8);

        assertTrue(PlanConformanceGate.checkStructural(git, work, baseline, plan).result().conformant());
    }

    @Test
    @DisplayName("EXCLUSION_ADDED is flagged when the exclusion is absent")
    void exclusionAddedFlaggedWhenAbsent() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);

        PlannedDependencyChange planned = new PlannedDependencyChange(
                "com.example:transitive-bad", null, null, "pom.xml",
                PlannedChangeType.EXCLUSION_ADDED, "exclude a vulnerable transitive dependency");
        AnalysisRemediationGroup plan = planWith(planned);

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM + "<!-- touched, no exclusion -->",
                StandardCharsets.UTF_8);

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);
        assertFalse(result.result().conformant());
        assertTrue(result.result().violations().get(0).contains("transitive-bad"));
    }

    // ---- OTHER ------------------------------------------------------------------------------------------
    //
    // OTHER exists precisely for changes Java cannot objectively verify -- it must never itself become a
    // plan-conformance violation, however vague its reason is. That is what requiresRiskyRouting() and the
    // risky singleton path are for: a plan containing OTHER is never auto-merged, always human-review-only.
    // PlanConformanceGate's only remaining job for OTHER is to record it as an informational,
    // non-blocking unverifiableNotes entry, and to keep checking every other, machine-verifiable
    // plannedChanges entry normally.

    @Test
    @DisplayName("a valid OTHER change with its own matching diff never fails plan conformance, and is "
            + "recorded as an unverifiable note")
    void validOtherChangeNeverFailsConformanceButIsRecordedAsUnverifiable() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);

        PlannedDependencyChange planned = new PlannedDependencyChange(
                "com.example:artifact", "1.0", "1.1", "pom.xml", PlannedChangeType.OTHER,
                "regenerate pom.xml's own vendor metadata block for com.example:artifact -- not a version "
                        + "bump, dependencyManagement edit, or exclusion");
        AnalysisRemediationGroup plan = planWith(planned);

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM + "<!-- vendor metadata regenerated -->",
                StandardCharsets.UTF_8);

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);
        assertTrue(result.result().conformant(), result.result().violations().toString());
        assertTrue(result.result().violations().isEmpty());
        assertEquals(1, result.result().unverifiableNotes().size());
        assertTrue(result.result().unverifiableNotes().get(0).contains("com.example:artifact"),
                result.result().unverifiableNotes().toString());
    }

    @Test
    @DisplayName("even a vague, unfalsifiable OTHER reason never fails plan conformance -- Claude is not "
            + "required to invent a more specific changeType for it")
    void vagueOtherReasonStillNeverFailsConformance() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);

        PlannedDependencyChange planned = new PlannedDependencyChange(
                "com.example:artifact", "1.0", "1.1", "pom.xml", PlannedChangeType.OTHER, "misc changes");
        AnalysisRemediationGroup plan = planWith(planned);

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM + "<!-- touched -->", StandardCharsets.UTF_8);

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);
        assertTrue(result.result().conformant(), result.result().violations().toString());
        assertEquals(1, result.result().unverifiableNotes().size());
    }

    @Test
    @DisplayName("VERSION_BUMP is objectively checked and OTHER is merely noted -- overall conformance "
            + "passes when the checkable part actually matches the plan")
    void versionBumpIsCheckedWhileOtherIsMerelyNoted() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);

        PlannedDependencyChange versionBump = versionBump("com.example:artifact", "1.0", "1.1");
        PlannedDependencyChange other = new PlannedDependencyChange(
                "com.example:artifact", null, null, "pom.xml", PlannedChangeType.OTHER,
                "also regenerate pom.xml's own vendor metadata alongside the version raise");
        AnalysisRemediationGroup plan = planWith(versionBump, other);

        Files.writeString(work.resolve("pom.xml"),
                BASELINE_POM.replace("<version>1.0</version>", "<version>1.1</version>")
                        + "<!-- vendor metadata regenerated -->",
                StandardCharsets.UTF_8);

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);
        assertTrue(result.result().conformant(), result.result().violations().toString());
        assertTrue(result.result().violations().isEmpty());
        assertEquals(1, result.result().unverifiableNotes().size());
        assertTrue(result.pendingVersionChecks().isEmpty(), "the literal version bump is checked immediately");
    }

    @Test
    @DisplayName("VERSION_BUMP mismatch is still flagged as a violation even when another plannedChanges "
            + "entry is OTHER")
    void versionBumpMismatchIsStillAViolationAlongsideOther() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);

        PlannedDependencyChange versionBump = versionBump("com.example:artifact", "1.0", "1.1");
        PlannedDependencyChange other = new PlannedDependencyChange(
                "com.example:artifact", null, null, "pom.xml", PlannedChangeType.OTHER, "misc changes");
        AnalysisRemediationGroup plan = planWith(versionBump, other);

        // The actual diff bumps to 1.2, not the planned 1.1 -- a genuine, machine-verifiable mismatch.
        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("<version>1.0</version>", "<version>1.2</version>"),
                StandardCharsets.UTF_8);

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);
        assertFalse(result.result().conformant());
        assertEquals(1, result.result().violations().size(), result.result().violations().toString());
        assertTrue(result.result().violations().get(0).contains("1.2"));
        assertEquals(1, result.result().unverifiableNotes().size(),
                "OTHER must still be recorded as a note even when a sibling entry fails conformance");
    }

    // ---- multi-module scoping: discovery is global, but resolution is local to the owning POM ---------
    //
    // Reproduces the real production defect (pilot 20260908-051442-b9af04): a legitimate remediation may
    // bump a property or BOM version in one POM while the module that actually consumes it -- unchanged
    // text, same effective value either way -- lives in a different file the diff never touches. Property/
    // dependencyManagement/BOM resolution is always scoped to the specific POM a declaration was found in
    // plus its own local <parent> chain -- never a same-named property or an unrelated sibling module's
    // management entry.

    private static String parentPom(String artifactId, String propertyValue) {
        return """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>%s</artifactId>
                  <version>1.0.0</version>
                  <packaging>pom</packaging>
                  <properties>
                    <lib.version>%s</lib.version>
                  </properties>
                </project>
                """.formatted(artifactId, propertyValue);
    }

    private static String childPomConsumingProperty() {
        return """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <parent>
                    <groupId>com.example</groupId>
                    <artifactId>parent</artifactId>
                    <version>1.0.0</version>
                    <relativePath>../parent/pom.xml</relativePath>
                  </parent>
                  <artifactId>child</artifactId>
                  <dependencies>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>artifact</artifactId>
                      <version>${lib.version}</version>
                    </dependency>
                  </dependencies>
                </project>
                """;
    }

    @Test
    @DisplayName("a property bumped only in a parent POM is conformant even though the child POM that "
            + "actually consumes it, reachable only via its own local <parent> chain, is never itself "
            + "touched by the diff")
    void propertyBumpViaLocalParentChainAcrossUnrelatedFilesIsConformant() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = commitFiles(work, Map.of(
                "parent/pom.xml", parentPom("parent", "1.0"),
                "child/pom.xml", childPomConsumingProperty()), "baseline");

        // Only the parent's own property changes; child/pom.xml is never rewritten again.
        Files.writeString(work.resolve("parent/pom.xml"), parentPom("parent", "1.1"), StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(
                List.of("parent/pom.xml"), versionBump("com.example:artifact", "1.0", "1.1"));
        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertTrue(result.result().conformant(), result.result().violations().toString());
        assertTrue(result.pendingVersionChecks().isEmpty());
    }

    @Test
    @DisplayName("a versionless dependency managed only in a parent POM, reached via its own local "
            + "<parent> chain, is conformant when the parent's own management entry is bumped")
    void versionlessDependencyManagedViaLocalParentChainIsConformant() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String parentWithManagement = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>parent</artifactId>
                  <version>1.0.0</version>
                  <packaging>pom</packaging>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>com.example</groupId>
                        <artifactId>artifact</artifactId>
                        <version>1.0</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """;
        String childVersionless = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <parent>
                    <groupId>com.example</groupId>
                    <artifactId>parent</artifactId>
                    <version>1.0.0</version>
                    <relativePath>../parent/pom.xml</relativePath>
                  </parent>
                  <artifactId>child</artifactId>
                  <dependencies>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>artifact</artifactId>
                    </dependency>
                  </dependencies>
                </project>
                """;
        String baseline = commitFiles(work, Map.of(
                "parent/pom.xml", parentWithManagement, "child/pom.xml", childVersionless), "baseline");

        Files.writeString(work.resolve("parent/pom.xml"),
                parentWithManagement.replace("<version>1.0</version>", "<version>1.1</version>"),
                StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(
                List.of("parent/pom.xml"), versionBump("com.example:artifact", "1.0", "1.1"));
        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertTrue(result.result().conformant(), result.result().violations().toString());
    }

    @Test
    @DisplayName("an unrelated coordinate that exists nowhere in the repository's POM files is still a "
            + "violation")
    void unrelatedCoordinateFoundNowhereStillFails() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);
        Files.writeString(work.resolve("pom.xml"), BASELINE_POM + "<!-- touched, unrelated -->",
                StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(versionBump("com.example:does-not-exist", "1.0", "1.1"));
        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertFalse(result.result().conformant());
        assertTrue(result.result().violations().get(0).contains("does-not-exist"));
    }

    @Test
    @DisplayName("a property, defined locally in the owning module, is used over a same-named property "
            + "defined in an unrelated sibling module")
    void samePropertyNameInUnrelatedModuleUsesOwnValueNotSiblings() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String moduleA = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>module-a</artifactId>
                  <version>1.0.0</version>
                  <properties>
                    <lib.version>1.0</lib.version>
                  </properties>
                  <dependencies>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>artifact</artifactId>
                      <version>${lib.version}</version>
                    </dependency>
                  </dependencies>
                </project>
                """;
        String moduleB = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>module-b</artifactId>
                  <version>1.0.0</version>
                  <properties>
                    <lib.version>9.9.9</lib.version>
                  </properties>
                </project>
                """;
        String baseline = commitFiles(work, Map.of("module-a/pom.xml", moduleA, "module-b/pom.xml", moduleB),
                "baseline");

        Files.writeString(work.resolve("module-a/pom.xml"),
                moduleA.replace("<lib.version>1.0</lib.version>", "<lib.version>1.1</lib.version>"),
                StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(
                List.of("module-a/pom.xml"), versionBump("com.example:artifact", "1.0", "1.1"));
        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertTrue(result.result().conformant(), result.result().violations().toString());
    }

    @Test
    @DisplayName("an unrelated BOM import in a sibling module never defers a versionless dependency that "
            + "has no local management entry of its own")
    void unrelatedBomImportInSiblingModuleDoesNotDeferVersionlessDependency() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String moduleA = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>module-a</artifactId>
                  <version>1.0.0</version>
                  <dependencies>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>artifact</artifactId>
                    </dependency>
                  </dependencies>
                </project>
                """;
        String moduleBWithUnrelatedBom = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>module-b</artifactId>
                  <version>1.0.0</version>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>com.other</groupId>
                        <artifactId>some-bom</artifactId>
                        <version>1.0</version>
                        <type>pom</type>
                        <scope>import</scope>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """;
        String baseline = commitFiles(work,
                Map.of("module-a/pom.xml", moduleA, "module-b/pom.xml", moduleBWithUnrelatedBom), "baseline");

        Files.writeString(work.resolve("module-a/pom.xml"), moduleA + "<!-- touched, no relevant change -->",
                StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(
                List.of("module-a/pom.xml"), versionBump("com.example:artifact", "1.0", "2.0"));
        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertFalse(result.result().conformant(),
                "module-b's own, unrelated BOM import must never defer module-a's unmanaged dependency");
        assertTrue(result.pendingVersionChecks().isEmpty());
    }

    @Test
    @DisplayName("a sibling module's dependencyManagement entry never manages a versionless dependency in "
            + "an unrelated module that does not inherit from it")
    void unrelatedDependencyManagementEntryInSiblingModuleDoesNotManageVersionlessDependency() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String moduleA = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>module-a</artifactId>
                  <version>1.0.0</version>
                  <dependencies>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>artifact</artifactId>
                    </dependency>
                  </dependencies>
                </project>
                """;
        // Same coordinates AND the same target version as the plan below -- if discovery ever leaked into
        // an unrelated sibling's management, this would make that bug produce a false CONFORMS.
        String moduleBWithMatchingManagement = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>module-b</artifactId>
                  <version>1.0.0</version>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>com.example</groupId>
                        <artifactId>artifact</artifactId>
                        <version>2.0</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """;
        String baseline = commitFiles(work,
                Map.of("module-a/pom.xml", moduleA, "module-b/pom.xml", moduleBWithMatchingManagement), "baseline");

        Files.writeString(work.resolve("module-a/pom.xml"), moduleA + "<!-- touched, no relevant change -->",
                StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(
                List.of("module-a/pom.xml"), versionBump("com.example:artifact", "1.0", "2.0"));
        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertFalse(result.result().conformant(),
                "module-b's management entry must never be treated as applicable to module-a");
    }

    @Test
    @DisplayName("a versionless dependency whose only <parent> reference points outside this repository's "
            + "own files is deferred to Phase B, not failed closed")
    void externalUnresolvableParentDefersVersionlessDependencyToPhaseB() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String childWithExternalParent = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <parent>
                    <groupId>com.example</groupId>
                    <artifactId>external-parent</artifactId>
                    <version>1.0.0</version>
                    <relativePath>../missing-parent/pom.xml</relativePath>
                  </parent>
                  <artifactId>child</artifactId>
                  <dependencies>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>artifact</artifactId>
                    </dependency>
                  </dependencies>
                </project>
                """;
        String baseline = commitFiles(work, Map.of("child/pom.xml", childWithExternalParent), "baseline");
        Files.writeString(work.resolve("child/pom.xml"), childWithExternalParent + "<!-- touched -->",
                StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(
                List.of("child/pom.xml"), versionBump("com.example:artifact", "1.0", "2.0"));
        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertTrue(result.result().conformant(), "unresolved locally, but must not fail closed either: "
                + result.result().violations());
        assertEquals(1, result.pendingVersionChecks().size(),
                "the external parent is a plausible boundary -- Phase B's real Maven decides this one");
    }

    // ---- baseline-vs-final no-op guard --------------------------------------------------------------
    //
    // A resolved value matching the plan's target is only a genuine remediation if the value actually
    // changed relative to baselineSha -- not just that the final state happens to already match.

    @Test
    @DisplayName("a VERSION_BUMP whose target was already present at the baseline is a no-op violation, "
            + "not a false CONFORMS")
    void versionBumpAlreadyAtTargetAtBaselineIsNoOpViolation() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String alreadyAtTarget = BASELINE_POM.replace("<version>1.0</version>", "<version>1.1</version>");
        Files.writeString(work.resolve("pom.xml"), alreadyAtTarget, StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "pom.xml");
        GitTestRepos.run(work, "git", "commit", "-q", "-m", "baseline pom");
        String baseline = git.currentHeadSha(work);

        // Implementation touches the file, but the dependency's own version was already 1.1.
        Files.writeString(work.resolve("pom.xml"), alreadyAtTarget + "<!-- touched, no relevant change -->",
                StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(versionBump("com.example:artifact", "1.0", "1.1"));
        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertFalse(result.result().conformant());
        assertTrue(result.result().violations().get(0).contains("already present at the baseline"),
                result.result().violations().toString());
    }

    @Test
    @DisplayName("removing a child's own property override so the effective version now comes from an "
            + "unchanged parent is a genuine change, never a false no-op")
    void propertyOverrideRemovalIsGenuineChangeNotFalseNoOp() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        // The parent's own property never changes, at baseline or at final.
        String parentPom = parentPom("parent", "2.0.0");
        String childWithOwnOverride = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <parent>
                    <groupId>com.example</groupId>
                    <artifactId>parent</artifactId>
                    <version>1.0.0</version>
                    <relativePath>../parent/pom.xml</relativePath>
                  </parent>
                  <artifactId>child</artifactId>
                  <properties>
                    <lib.version>1.0.0</lib.version>
                  </properties>
                  <dependencies>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>artifact</artifactId>
                      <version>${lib.version}</version>
                    </dependency>
                  </dependencies>
                </project>
                """;
        String childWithoutOverride = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <parent>
                    <groupId>com.example</groupId>
                    <artifactId>parent</artifactId>
                    <version>1.0.0</version>
                    <relativePath>../parent/pom.xml</relativePath>
                  </parent>
                  <artifactId>child</artifactId>
                  <dependencies>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>artifact</artifactId>
                      <version>${lib.version}</version>
                    </dependency>
                  </dependencies>
                </project>
                """;
        String baseline = commitFiles(work,
                Map.of("parent/pom.xml", parentPom, "child/pom.xml", childWithOwnOverride), "baseline");

        // Implementation removes the child's own override -- the parent's property text never changes.
        Files.writeString(work.resolve("child/pom.xml"), childWithoutOverride, StandardCharsets.UTF_8);

        AnalysisRemediationGroup plan = planWith(
                List.of("child/pom.xml"), versionBump("com.example:artifact", "1.0.0", "2.0.0"));
        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);

        assertTrue(result.result().conformant(), "final resolves through the parent (2.0.0), baseline "
                + "resolved through the child's own override (1.0.0) -- a genuine change: "
                + result.result().violations());
    }

    // ---- file scope -----------------------------------------------------------------------------------

    @Test
    @DisplayName("a changed file outside the plan's allowed set is flagged regardless of changeType")
    void unauthorizedFileChangeIsFlaggedRegardlessOfChangeType() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);

        AnalysisRemediationGroup plan = planWith(versionBump("com.example:artifact", "1.0", "1.1"));

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("1.0", "1.1"), StandardCharsets.UTF_8);
        Files.writeString(work.resolve("unrelated-file.txt"), "not part of the plan\n", StandardCharsets.UTF_8);
        GitTestRepos.run(work, "git", "add", "unrelated-file.txt");

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);
        assertFalse(result.result().conformant());
        assertTrue(result.result().violations().stream().anyMatch(v -> v.contains("unrelated-file.txt")));
    }

    @Test
    @DisplayName("a brand-new untracked file outside the plan's scope is flagged too, not silently missed")
    void newUntrackedUnauthorizedFileIsFlagged() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);

        AnalysisRemediationGroup plan = planWith(versionBump("com.example:artifact", "1.0", "1.1"));

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("1.0", "1.1"), StandardCharsets.UTF_8);
        // A brand-new, never-tracked file: a plain "git diff <sha>" alone would never show this at all.
        Files.writeString(work.resolve("new-unauthorized-file.txt"), "not part of the plan\n", StandardCharsets.UTF_8);

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);
        assertFalse(result.result().conformant());
        assertTrue(result.result().violations().stream().anyMatch(v -> v.contains("new-unauthorized-file.txt")));
    }

    @Test
    @DisplayName("an extra narrative-only affectedFiles entry that was never actually touched is not flagged "
            + "-- it is an allowance, not a requirement")
    void narrativeOnlyAffectedFileIsAllowanceNotRequirement() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);

        AnalysisRemediationGroup plan = planWith(
                List.of("pom.xml", "parent/pom.xml"), versionBump("com.example:artifact", "1.0", "1.1"));

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("1.0", "1.1"), StandardCharsets.UTF_8);

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);
        assertTrue(result.result().conformant(), result.result().violations().toString());
    }
}
