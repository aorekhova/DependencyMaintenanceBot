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
    //
    // dependencyCoordinates is always the HOST dependency the exclusion is added to; excludedCoordinates
    // (required, non-empty) names what is actually excluded from it -- run 20260920-052841-210614: Claude
    // #1 set dependencyCoordinates to the host (org.kordamp.json:json-lib-core) and named the excluded
    // coordinates (junit:junit, org.slf4j:jcl-over-slf4j) only in reason's prose; PlanConformanceGate at
    // the time treated dependencyCoordinates itself as the excluded coordinate, so it went looking for an
    // exclusion of json-lib-core that could never exist. These tests check the fixed, fully structural
    // contract: the exclusion must be nested under the named host's own <dependency> element, never merely
    // present somewhere in the repository's POM files.

    private static PlannedDependencyChange exclusionAdded(String host, String... excluded) {
        return new PlannedDependencyChange(host, null, null, "pom.xml", PlannedChangeType.EXCLUSION_ADDED,
                "exclude vulnerable transitive dependency(ies) from " + host, List.of(excluded));
    }

    @Test
    @DisplayName("EXCLUSION_ADDED is conformant only when the exact exclusion exists nested under the "
            + "named host dependency")
    void exclusionAddedConformantOnlyWhenExclusionExistsUnderHost() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);

        PlannedDependencyChange planned = exclusionAdded("com.example:artifact", "com.example:transitive-bad");
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
    @DisplayName("EXCLUSION_ADDED is flagged when the exclusion is absent entirely")
    void exclusionAddedFlaggedWhenAbsent() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);

        PlannedDependencyChange planned = exclusionAdded("com.example:artifact", "com.example:transitive-bad");
        AnalysisRemediationGroup plan = planWith(planned);

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM + "<!-- touched, no exclusion -->",
                StandardCharsets.UTF_8);

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan);
        assertFalse(result.result().conformant());
        assertTrue(result.result().violations().get(0).contains("transitive-bad"));
    }

    @Test
    @DisplayName("run 20260920-052841-210614's exact shape: the excluded coordinate exists in the "
            + "repository, but nested under a different dependency than the one the plan names as the "
            + "host -- still flagged, never accepted just because the coordinate exists somewhere")
    void exclusionAddedFlaggedWhenExclusionExistsUnderTheWrongHost() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = commitFiles(work, Map.of("pom.xml", """
                <project>
                  <dependencies>
                    <dependency>
                      <groupId>org.kordamp.json</groupId>
                      <artifactId>json-lib-core</artifactId>
                      <version>2.1</version>
                    </dependency>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>unrelated-host</artifactId>
                      <version>1.0</version>
                    </dependency>
                  </dependencies>
                </project>
                """), "baseline");

        // The exclusion for junit:junit ends up nested under the wrong host (unrelated-host), never under
        // the plan's own named host (org.kordamp.json:json-lib-core).
        Files.writeString(work.resolve("pom.xml"), """
                <project>
                  <dependencies>
                    <dependency>
                      <groupId>org.kordamp.json</groupId>
                      <artifactId>json-lib-core</artifactId>
                      <version>2.1</version>
                    </dependency>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>unrelated-host</artifactId>
                      <version>1.0</version>
                      <exclusions>
                        <exclusion>
                          <groupId>junit</groupId>
                          <artifactId>junit</artifactId>
                        </exclusion>
                      </exclusions>
                    </dependency>
                  </dependencies>
                </project>
                """, StandardCharsets.UTF_8);

        PlannedDependencyChange planned = exclusionAdded("org.kordamp.json:json-lib-core", "junit:junit");
        var result = PlanConformanceGate.checkStructural(git, work, baseline, planWith(planned));

        assertFalse(result.result().conformant());
        assertTrue(result.result().violations().get(0).contains("junit:junit"), result.result().violations().toString());
    }

    @Test
    @DisplayName("one EXCLUSION_ADDED entry naming several excluded coordinates under the same host is "
            + "conformant only once every one of them is actually nested there")
    void exclusionAddedWithMultipleExcludedCoordinatesRequiresEveryOne() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);

        PlannedDependencyChange planned = exclusionAdded(
                "com.example:artifact", "junit:junit", "org.slf4j:jcl-over-slf4j");
        AnalysisRemediationGroup plan = planWith(planned);

        // Only one of the two planned exclusions is actually present.
        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("</dependency>", """
                    <exclusions>
                      <exclusion>
                        <groupId>junit</groupId>
                        <artifactId>junit</artifactId>
                      </exclusion>
                    </exclusions>
                  </dependency>
                """), StandardCharsets.UTF_8);

        var partial = PlanConformanceGate.checkStructural(git, work, baseline, plan);
        assertFalse(partial.result().conformant());
        assertTrue(partial.result().violations().get(0).contains("jcl-over-slf4j"),
                partial.result().violations().toString());
        assertFalse(partial.result().violations().get(0).contains("junit:junit"),
                "the exclusion that IS present must not also be named as missing: "
                        + partial.result().violations());

        // Both are now present -- conformant.
        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("</dependency>", """
                    <exclusions>
                      <exclusion>
                        <groupId>junit</groupId>
                        <artifactId>junit</artifactId>
                      </exclusion>
                      <exclusion>
                        <groupId>org.slf4j</groupId>
                        <artifactId>jcl-over-slf4j</artifactId>
                      </exclusion>
                    </exclusions>
                  </dependency>
                """), StandardCharsets.UTF_8);

        assertTrue(PlanConformanceGate.checkStructural(git, work, baseline, plan).result().conformant());
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

    // ---- failure-driven, narrow, per-stage scope extension (run 20260919-221201-636b49, json-lib case) ----

    private static AnalysisRemediationGroup planWithMembers(
            List<String> memberCoordinates, PlannedDependencyChange... changes) {
        return new AnalysisRemediationGroup(
                "g", memberCoordinates, List.of(), "narrative", null, null, null, null, null, null, null,
                List.of("pom.xml"), null, null, null, null, List.of(), List.of(), List.of(changes));
    }

    private static com.tungsten.depbot.implementation.RepairContext dependencyValidationRepairContext() {
        return new com.tungsten.depbot.implementation.RepairContext(
                "diff", com.tungsten.depbot.remediation.RejectionStage.DEPENDENCY_VALIDATION,
                com.tungsten.depbot.validation.ValidationOutcome.failed(
                        "the vulnerable coordinate still resolves via a companion module", List.of(), ""),
                null, null, null, List.of(), "dependency validation failed");
    }

    private static final String COMPANION_POM = """
            <project>
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>test-services</artifactId>
              <version>1.0.0</version>
              <dependencies>
                <dependency>
                  <groupId>com.example</groupId>
                  <artifactId>jaxb-companion</artifactId>
                  <version>2.2</version>
                </dependency>
              </dependencies>
            </project>
            """;

    @Test
    @DisplayName("DEPENDENCY_VALIDATION retry: an exclusion-only extra file targeting the plan's own "
            + "member coordinate is accepted as a narrow scope extension")
    void dependencyValidationRetryAcceptsNarrowExclusionOnlyExtension() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = commitFiles(work,
                Map.of("pom.xml", BASELINE_POM, "test-services/pom.xml", COMPANION_POM), "baseline");

        AnalysisRemediationGroup plan = planWithMembers(
                List.of("com.example:artifact"), versionBump("com.example:artifact", "1.0", "1.1"));

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("1.0", "1.1"), StandardCharsets.UTF_8);
        Files.writeString(work.resolve("test-services/pom.xml"), COMPANION_POM.replace(
                "</dependency>",
                "<exclusions><exclusion><groupId>com.example</groupId><artifactId>artifact</artifactId>"
                        + "</exclusion></exclusions></dependency>"));

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan, dependencyValidationRepairContext());

        assertTrue(result.result().conformant(), result.result().violations().toString());
        assertFalse(result.result().scopeExtensions().isEmpty());
        assertTrue(result.result().scopeExtensions().get(0).contains("test-services/pom.xml"));
    }

    @Test
    @DisplayName("DEPENDENCY_VALIDATION retry: the same extra file is rejected outright on attempt 1 "
            + "(repairContext is null) -- the 4-arg overload behaves identically")
    void extraFileNeverAllowedWhenRepairContextIsNull() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = commitFiles(work,
                Map.of("pom.xml", BASELINE_POM, "test-services/pom.xml", COMPANION_POM), "baseline");

        AnalysisRemediationGroup plan = planWithMembers(
                List.of("com.example:artifact"), versionBump("com.example:artifact", "1.0", "1.1"));

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("1.0", "1.1"), StandardCharsets.UTF_8);
        Files.writeString(work.resolve("test-services/pom.xml"), COMPANION_POM.replace(
                "</dependency>",
                "<exclusions><exclusion><groupId>com.example</groupId><artifactId>artifact</artifactId>"
                        + "</exclusion></exclusions></dependency>"));

        var withoutRepair = PlanConformanceGate.checkStructural(git, work, baseline, plan);
        var withNullRepair = PlanConformanceGate.checkStructural(git, work, baseline, plan, null);

        assertFalse(withoutRepair.result().conformant());
        assertFalse(withNullRepair.result().conformant());
        assertTrue(withoutRepair.result().violations().stream().anyMatch(v -> v.contains("test-services/pom.xml")));
    }

    @Test
    @DisplayName("DEPENDENCY_VALIDATION retry: an extra file that also changes something beyond exclusions "
            + "is still rejected")
    void extraFileWithNonExclusionChangeIsRejected() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = commitFiles(work,
                Map.of("pom.xml", BASELINE_POM, "test-services/pom.xml", COMPANION_POM), "baseline");

        AnalysisRemediationGroup plan = planWithMembers(
                List.of("com.example:artifact"), versionBump("com.example:artifact", "1.0", "1.1"));

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("1.0", "1.1"), StandardCharsets.UTF_8);
        // Adds the exclusion AND bumps the companion's own version -- not exclusion-only.
        Files.writeString(work.resolve("test-services/pom.xml"), COMPANION_POM
                .replace("<version>2.2</version>", "<version>2.3</version>")
                .replace("</dependency>",
                        "<exclusions><exclusion><groupId>com.example</groupId><artifactId>artifact</artifactId>"
                                + "</exclusion></exclusions></dependency>"));

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan, dependencyValidationRepairContext());

        assertFalse(result.result().conformant());
        assertTrue(result.result().violations().stream().anyMatch(v -> v.contains("test-services/pom.xml")));
    }

    @Test
    @DisplayName("DEPENDENCY_VALIDATION retry: an exclusion for a coordinate the plan does not target is "
            + "still rejected")
    void extraFileExclusionForUnrelatedCoordinateIsRejected() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = commitFiles(work,
                Map.of("pom.xml", BASELINE_POM, "test-services/pom.xml", COMPANION_POM), "baseline");

        AnalysisRemediationGroup plan = planWithMembers(
                List.of("com.example:artifact"), versionBump("com.example:artifact", "1.0", "1.1"));

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("1.0", "1.1"), StandardCharsets.UTF_8);
        Files.writeString(work.resolve("test-services/pom.xml"), COMPANION_POM.replace(
                "</dependency>",
                "<exclusions><exclusion><groupId>com.example</groupId><artifactId>unrelated-library</artifactId>"
                        + "</exclusion></exclusions></dependency>"));

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan, dependencyValidationRepairContext());

        assertFalse(result.result().conformant());
    }

    @Test
    @DisplayName("DEPENDENCY_VALIDATION retry: removing a pre-existing exclusion is still rejected -- no "
            + "silent un-excludes")
    void extraFileRemovingAnExclusionIsRejected() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String companionWithExclusion = COMPANION_POM.replace(
                "</dependency>",
                "<exclusions><exclusion><groupId>com.example</groupId><artifactId>artifact</artifactId>"
                        + "</exclusion></exclusions></dependency>");
        String baseline = commitFiles(work,
                Map.of("pom.xml", BASELINE_POM, "test-services/pom.xml", companionWithExclusion), "baseline");

        AnalysisRemediationGroup plan = planWithMembers(
                List.of("com.example:artifact"), versionBump("com.example:artifact", "1.0", "1.1"));

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("1.0", "1.1"), StandardCharsets.UTF_8);
        Files.writeString(work.resolve("test-services/pom.xml"), COMPANION_POM); // exclusion removed

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan, dependencyValidationRepairContext());

        assertFalse(result.result().conformant());
    }

    @Test
    @DisplayName("the exclusion-only extension is never allowed for a FULL_BUILD failure stage -- each "
            + "stage's rule is independent")
    void scopeExtensionNeverAllowedWhenFailedStageIsFullBuild() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = commitFiles(work,
                Map.of("pom.xml", BASELINE_POM, "test-services/pom.xml", COMPANION_POM), "baseline");

        AnalysisRemediationGroup plan = planWithMembers(
                List.of("com.example:artifact"), versionBump("com.example:artifact", "1.0", "1.1"));

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("1.0", "1.1"), StandardCharsets.UTF_8);
        Files.writeString(work.resolve("test-services/pom.xml"), COMPANION_POM.replace(
                "</dependency>",
                "<exclusions><exclusion><groupId>com.example</groupId><artifactId>artifact</artifactId>"
                        + "</exclusion></exclusions></dependency>"));

        com.tungsten.depbot.implementation.RepairContext fullBuildRepair =
                new com.tungsten.depbot.implementation.RepairContext(
                        "diff", com.tungsten.depbot.remediation.RejectionStage.FULL_BUILD, null,
                        com.tungsten.depbot.validation.ValidationOutcome.failed("build failed", List.of(), ""),
                        null, null, List.of(), "full build failed");

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan, fullBuildRepair);

        assertFalse(result.result().conformant(),
                "an exclusion-only edit must not be accepted under a stage it has no rule for");
    }

    // ---- PLAN_DEVIATION_REQUIRED: Java's own discovered control point ------------------------------

    @Test
    @DisplayName("PLAN_DEVIATION_REQUIRED retry: an extra file that Java's own POM discovery proves is a "
            + "planned coordinate's real dependencyManagement control point is accepted")
    void planDeviationRetryAcceptsDiscoveredControlPointExtension() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String parentPom = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>parent</artifactId>
                  <version>1.0.0</version>
                </project>
                """;
        String childPom = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <parent>
                    <groupId>com.example</groupId>
                    <artifactId>parent</artifactId>
                    <version>1.0.0</version>
                    <relativePath>../pom.xml</relativePath>
                  </parent>
                  <artifactId>app</artifactId>
                </project>
                """;
        String baseline = commitFiles(work, Map.of("pom.xml", parentPom, "app/pom.xml", childPom), "baseline");

        // The plan only names pom.xml as affected -- the real control point (a new dependencyManagement
        // entry) turns out to belong in the parent, discovered mechanically, never asserted by Claude.
        AnalysisRemediationGroup plan = planWithMembers(List.of("com.example:artifact"), new PlannedDependencyChange(
                "com.example:artifact", null, "1.1", "pom.xml",
                PlannedChangeType.DEPENDENCY_MANAGEMENT_ADDITION, "add a managed entry"));

        Files.writeString(work.resolve("app/pom.xml"), childPom); // unchanged
        Files.writeString(work.resolve("pom.xml"), parentPom.replace("</project>", """
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>com.example</groupId>
                        <artifactId>artifact</artifactId>
                        <version>1.1</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """));

        com.tungsten.depbot.implementation.RepairContext planDeviationRepair =
                new com.tungsten.depbot.implementation.RepairContext(
                        "diff", com.tungsten.depbot.remediation.RejectionStage.PLAN_DEVIATION_REQUIRED, null, null,
                        null, null, List.of("unauthorized file changed: pom.xml"), "plan deviation");

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan, planDeviationRepair);

        assertTrue(result.result().conformant(), result.result().violations().toString());
    }

    // ---- FULL_BUILD/CUMULATIVE_JENKINS: evidence-named file -----------------------------------------

    @Test
    @DisplayName("FULL_BUILD retry: a brand-new file named in the evidence is still rejected -- never "
            + "allowed through this rule")
    void fullBuildRetryRejectsBrandNewFile() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = baselineSha(work);

        AnalysisRemediationGroup plan = planWithMembers(
                List.of("com.example:artifact"), versionBump("com.example:artifact", "1.0", "1.1"));

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("1.0", "1.1"), StandardCharsets.UTF_8);
        Files.createDirectories(work.resolve("src/main/java/com/example"));
        Files.writeString(work.resolve("src/main/java/com/example/Compat.java"), "class Compat {}\n");
        GitTestRepos.run(work, "git", "add", "src/main/java/com/example/Compat.java");

        com.tungsten.depbot.implementation.RepairContext fullBuildRepair =
                new com.tungsten.depbot.implementation.RepairContext(
                        "diff", com.tungsten.depbot.remediation.RejectionStage.FULL_BUILD, null,
                        com.tungsten.depbot.validation.ValidationOutcome.failed(
                                "cannot find symbol in src/main/java/com/example/Compat.java", List.of(), ""),
                        null, null, List.of(), "full build failed");

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan, fullBuildRepair);

        assertFalse(result.result().conformant(), "a brand-new file is never accepted through this rule");
    }

    @Test
    @DisplayName("FULL_BUILD retry: a base-name-only match (not the full path) in the evidence is not "
            + "enough -- the full, exact relative path must be named")
    void fullBuildRetryRequiresFullPathMatch() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String companionJava = "class Compat { void old() {} }\n";
        String baseline = commitFiles(work,
                Map.of("pom.xml", BASELINE_POM, "src/main/java/com/example/Compat.java", companionJava),
                "baseline");

        AnalysisRemediationGroup plan = planWithMembers(
                List.of("com.example:artifact"), versionBump("com.example:artifact", "1.0", "1.1"));

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("1.0", "1.1"), StandardCharsets.UTF_8);
        Files.writeString(work.resolve("src/main/java/com/example/Compat.java"),
                "class Compat { void updated() {} }\n");

        com.tungsten.depbot.implementation.RepairContext fullBuildRepair =
                new com.tungsten.depbot.implementation.RepairContext(
                        "diff", com.tungsten.depbot.remediation.RejectionStage.FULL_BUILD, null,
                        com.tungsten.depbot.validation.ValidationOutcome.failed(
                                "cannot find symbol in Compat.java", List.of(), ""),
                        null, null, List.of(), "full build failed");

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan, fullBuildRepair);

        assertFalse(result.result().conformant(), "only the base filename was named, not the full path");
    }

    @Test
    @DisplayName("FULL_BUILD retry: a non-POM compatibility file named in the evidence is accepted, and "
            + "the resulting outcome carries the forces-human-review marker")
    void fullBuildRetryAcceptsEvidenceNamedCompatibilityFile() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String companionJava = "class Compat { void old() {} }\n";
        String baseline = commitFiles(work,
                Map.of("pom.xml", BASELINE_POM, "src/main/java/com/example/Compat.java", companionJava),
                "baseline");

        AnalysisRemediationGroup plan = planWithMembers(
                List.of("com.example:artifact"), versionBump("com.example:artifact", "1.0", "1.1"));

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("1.0", "1.1"), StandardCharsets.UTF_8);
        Files.writeString(work.resolve("src/main/java/com/example/Compat.java"),
                "class Compat { void updated() {} }\n");

        com.tungsten.depbot.implementation.RepairContext fullBuildRepair =
                new com.tungsten.depbot.implementation.RepairContext(
                        "diff", com.tungsten.depbot.remediation.RejectionStage.FULL_BUILD, null,
                        com.tungsten.depbot.validation.ValidationOutcome.failed(
                                "cannot find symbol in src/main/java/com/example/Compat.java", List.of(), ""),
                        null, null, List.of(), "full build failed");

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan, fullBuildRepair);

        assertTrue(result.result().conformant(), result.result().violations().toString());
        assertTrue(result.result().scopeExtensions().stream().anyMatch(s -> s.contains("FORCES_HUMAN_REVIEW")));
    }

    @Test
    @DisplayName("FULL_BUILD retry: a POM file named in the evidence gets no free pass for its Maven "
            + "content -- a non-exclusion, non-discovered-control-point edit is still rejected")
    void fullBuildRetryPomFileStillNeedsMechanicalJustification() throws Exception {
        Path work = GitTestRepos.createOriginAndClone(tempDir);
        String baseline = commitFiles(work,
                Map.of("pom.xml", BASELINE_POM, "test-services/pom.xml", COMPANION_POM), "baseline");

        AnalysisRemediationGroup plan = planWithMembers(
                List.of("com.example:artifact"), versionBump("com.example:artifact", "1.0", "1.1"));

        Files.writeString(work.resolve("pom.xml"), BASELINE_POM.replace("1.0", "1.1"), StandardCharsets.UTF_8);
        // Bumps the companion's own unrelated version -- not an exclusion, not a discovered control point
        // for anything the plan actually targets.
        Files.writeString(work.resolve("test-services/pom.xml"),
                COMPANION_POM.replace("<version>2.2</version>", "<version>2.3</version>"));

        com.tungsten.depbot.implementation.RepairContext fullBuildRepair =
                new com.tungsten.depbot.implementation.RepairContext(
                        "diff", com.tungsten.depbot.remediation.RejectionStage.FULL_BUILD, null,
                        com.tungsten.depbot.validation.ValidationOutcome.failed(
                                "test-services/pom.xml needs a bump too", List.of(), ""),
                        null, null, List.of(), "full build failed");

        var result = PlanConformanceGate.checkStructural(git, work, baseline, plan, fullBuildRepair);

        assertFalse(result.result().conformant());
    }
}
