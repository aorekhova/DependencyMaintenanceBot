package com.tungsten.depbot.publication;

import com.tungsten.depbot.assessment.AutomationSafety;
import com.tungsten.depbot.assessment.PlannedChangeType;
import com.tungsten.depbot.assessment.PlannedDependencyChange;
import com.tungsten.depbot.jenkins.JenkinsValidationOutcome;
import com.tungsten.depbot.jenkins.JenkinsValidationStatus;
import com.tungsten.depbot.remediation.RemediationReport;
import com.tungsten.depbot.validation.ValidationStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemediationReportMarkdownRendererTest {

    private static final String FULL_BUILD_COMMAND = "mvn.cmd -B clean package";

    private final RemediationReportMarkdownRenderer renderer = new RemediationReportMarkdownRenderer();

    private static RemediationReport report(ValidationStatus dependencyStatus, ValidationStatus fullBuildStatus) {
        return report(dependencyStatus, fullBuildStatus, null, null);
    }

    private static RemediationReport report(
            ValidationStatus dependencyStatus, ValidationStatus fullBuildStatus,
            JenkinsValidationOutcome isolatedJenkins, JenkinsValidationOutcome integrationJenkins) {
        return report(dependencyStatus, fullBuildStatus, isolatedJenkins, integrationJenkins,
                List.of(), List.of(), Map.of(), FULL_BUILD_COMMAND);
    }

    private static RemediationReport report(
            ValidationStatus dependencyStatus, ValidationStatus fullBuildStatus,
            JenkinsValidationOutcome isolatedJenkins, JenkinsValidationOutcome integrationJenkins,
            List<String> remainingWork, List<PlannedDependencyChange> plannedChanges,
            Map<String, String> resolvedVersionsByCoordinates, String fullBuildValidationCommand) {
        return new RemediationReport(
                "1.0", "1438774abc", "g-mchange",
                List.of("com.mchange:c3p0", "com.mchange:mchange-commons-java"),
                "raised c3p0 and mchange-commons-java to their fixed versions",
                "com.mchange:c3p0: CVE-2026-X | com.mchange:mchange-commons-java: CVE-2026-Y",
                "the analysis recommended a coordinated bump of both dependencies together",
                List.of("pom.xml"),
                "Dependency-resolution gate: PASSED | Full build (" + FULL_BUILD_COMMAND + "): " + fullBuildStatus,
                List.of(
                        new RemediationReport.VersionChange("com.mchange:c3p0", "0.13.0", "0.14.0"),
                        new RemediationReport.VersionChange(
                                "com.mchange:mchange-commons-java", "0.5.0", "0.6.0")),
                dependencyStatus, fullBuildStatus, isolatedJenkins, integrationJenkins,
                null, null, null, null, null,
                fullBuildValidationCommand,
                remainingWork,
                plannedChanges,
                List.of("raised c3p0 to 0.14.0", "raised mchange-commons-java to 0.6.0"),
                List.of("Dependency-resolution gate: PASSED (ok)",
                        "Full build (" + FULL_BUILD_COMMAND + "): " + fullBuildStatus + " (ok)"),
                resolvedVersionsByCoordinates);
    }

    private static JenkinsValidationOutcome jenkinsOutcome(JenkinsValidationStatus status) {
        return new JenkinsValidationOutcome(status, "WebApplicationDependencyValidation", 42,
                "https://jenkins.example.invalid/job/x/42/", "baseSha123", "candidateSha456", "treeSha789",
                120L, "Jenkins reported result " + status);
    }

    @Test
    @DisplayName("the report shows the group, every library's old and new version, and the commit SHA")
    void showsGroupLibrariesVersionsAndCommit() {
        String markdown = renderer.render(report(ValidationStatus.PASSED, ValidationStatus.PASSED));

        assertTrue(markdown.contains("g-mchange"), markdown);
        assertTrue(markdown.contains("com.mchange:c3p0"), markdown);
        assertTrue(markdown.contains("0.13.0"), markdown);
        assertTrue(markdown.contains("0.14.0"), markdown);
        assertTrue(markdown.contains("com.mchange:mchange-commons-java"), markdown);
        assertTrue(markdown.contains("0.5.0"), markdown);
        assertTrue(markdown.contains("0.6.0"), markdown);
        assertTrue(markdown.contains("1438774abc"), markdown);
    }

    @Test
    @DisplayName("a passed full build is called out by name and the real, actually-executed command, "
            + "unmistakably -- never a hard-coded literal")
    void passedFullBuildIsExplicit() {
        String markdown = renderer.render(report(ValidationStatus.PASSED, ValidationStatus.PASSED));

        assertTrue(markdown.contains("Full application build after this commit"), markdown);
        assertTrue(markdown.contains(FULL_BUILD_COMMAND), markdown);
        assertTrue(markdown.contains("PASSED"), markdown);
    }

    @Test
    @DisplayName("when no full-build command was recorded, the report falls back to a generic, "
            + "non-committal phrase -- never a guessed or hard-coded command")
    void missingFullBuildCommandFallsBackToGenericPhrase() {
        String markdown = renderer.render(report(ValidationStatus.PASSED, ValidationStatus.NOT_RUN,
                null, null, List.of(), List.of(), Map.of(), null));

        assertTrue(markdown.contains("Full application build after this commit (the full application build)"),
                markdown);
        assertTrue(markdown.contains("- ⚠ Full application build after this commit (the full application "
                + "build): NOT RUN"), markdown);
    }

    @Test
    @DisplayName("a failed full build never reads as fully validated")
    void failedFullBuildIsNeverClaimedAsValidated() {
        String markdown = renderer.render(report(ValidationStatus.PASSED, ValidationStatus.FAILED));

        assertTrue(markdown.contains("FAILED"), markdown);
        assertTrue(markdown.contains("not** fully validated") || markdown.contains("not fully validated"), markdown);
    }

    @Test
    @DisplayName("a full build that never ran is not fully validated either")
    void notRunFullBuildIsNotClaimedAsValidated() {
        String markdown = renderer.render(report(ValidationStatus.PASSED, ValidationStatus.NOT_RUN));

        assertTrue(markdown.contains("NOT RUN"), markdown);
        assertFalse(markdown.contains("✓ Full application build"), markdown);
    }

    @Test
    @DisplayName("a null report is rejected rather than rendering a broken document")
    void nullReportIsRejected() {
        assertThrows(NullPointerException.class, () -> renderer.render(null));
    }

    @Test
    @DisplayName("both Jenkins sections render NOT RUN when neither gate was ever reached")
    void bothJenkinsSectionsAreNotRunWhenAbsent() {
        String markdown = renderer.render(report(ValidationStatus.PASSED, ValidationStatus.PASSED));

        assertTrue(markdown.contains("Cumulative Jenkins validation"), markdown);
        assertTrue(markdown.contains("Final integration Jenkins validation"), markdown);
        assertTrue(markdown.contains("NOT RUN"), markdown);
    }

    @Test
    @DisplayName("each Jenkins section shows its own structural facts, bot-owned, not Claude prose")
    void jenkinsSectionsShowStructuralFacts() {
        String markdown = renderer.render(report(ValidationStatus.PASSED, ValidationStatus.PASSED,
                jenkinsOutcome(JenkinsValidationStatus.SUCCESS), jenkinsOutcome(JenkinsValidationStatus.SUCCESS)));

        assertTrue(markdown.contains("WebApplicationDependencyValidation"), markdown);
        assertTrue(markdown.contains("baseSha123"), markdown);
        assertTrue(markdown.contains("candidateSha456"), markdown);
        assertTrue(markdown.contains("treeSha789"), markdown);
        assertTrue(markdown.contains("https://jenkins.example.invalid/job/x/42/"), markdown);
    }

    @Test
    @DisplayName("a successful isolated gate never reads as fully validated when integration failed")
    void successfulIsolatedGateNeverImpliesFullValidationWhenIntegrationFailed() {
        RemediationReport report = report(ValidationStatus.PASSED, ValidationStatus.PASSED,
                jenkinsOutcome(JenkinsValidationStatus.SUCCESS), jenkinsOutcome(JenkinsValidationStatus.FAILED));
        String markdown = renderer.render(report);

        assertFalse(report.jenkinsValidated());
        assertTrue(markdown.contains("✓ SUCCESS"), markdown);
        assertTrue(markdown.contains("✗ FAILED"), markdown);
    }

    @Test
    @DisplayName("the document opens with a compact title/status and an at-a-glance table before any "
            + "long-form content, so a reviewer can orient in seconds")
    void opensWithDecisionFirstSummary() {
        String markdown = renderer.render(report(ValidationStatus.PASSED, ValidationStatus.PASSED));

        int atAGlance = markdown.indexOf("At a glance");
        int findingsTable = markdown.indexOf("Vulnerability findings");
        int fullEvidence = markdown.indexOf("Full investigation evidence");
        assertTrue(atAGlance >= 0 && atAGlance < findingsTable, markdown);
        assertTrue(findingsTable < fullEvidence, markdown);
        assertTrue(markdown.contains("Recommended action"), markdown);
        assertTrue(markdown.contains("Validation results"), markdown);
    }

    @Test
    @DisplayName("a risky-but-successful group gets an explicit banner naming the residual risk, and an "
            + "ordinary automatic group does not")
    void riskyGroupGetsExplicitBanner() {
        RemediationReport ordinary = report(ValidationStatus.PASSED, ValidationStatus.PASSED);
        RemediationReport risky = new RemediationReport(
                ordinary.schemaVersion(), ordinary.commitSha(), ordinary.groupId(), ordinary.memberCoordinates(),
                ordinary.whatChanged(), ordinary.whyNecessary(), ordinary.whyThisRemediation(),
                ordinary.whereChanged(), ordinary.validationPerformed(), ordinary.versionChanges(),
                ordinary.dependencyValidationStatus(), ordinary.fullBuildValidationStatus(), null, null,
                null, null, AutomationSafety.HUMAN_REVIEW_REQUIRED, "touches a shared, coordinated dependency",
                "touches a shared, coordinated dependency", ordinary.fullBuildValidationCommand(),
                ordinary.remainingWork(), ordinary.plannedChanges(), ordinary.whatChangedItems(),
                ordinary.validationPerformedItems(), ordinary.resolvedVersionsByCoordinates());

        String ordinaryMarkdown = renderer.render(ordinary);
        String riskyMarkdown = renderer.render(risky);

        assertFalse(ordinaryMarkdown.contains("Risky change, automated successfully"), ordinaryMarkdown);
        assertTrue(riskyMarkdown.contains("Risky change, automated successfully"), riskyMarkdown);
        assertTrue(riskyMarkdown.contains("touches a shared, coordinated dependency"), riskyMarkdown);
        assertTrue(riskyMarkdown.contains("requires human review before merge"), riskyMarkdown);
    }

    @Test
    @DisplayName("long-form investigation detail (why necessary, why this remediation, full Jenkins facts "
            + "including a console log excerpt) lives inside a collapsible details section at the bottom, "
            + "not removed, just no longer first")
    void longFormEvidenceIsCollapsibleAtTheBottom() {
        JenkinsValidationOutcome withLog = new JenkinsValidationOutcome(
                JenkinsValidationStatus.FAILED, "WebApplicationDependencyValidation", 42,
                "https://jenkins.example.invalid/job/x/42/", "baseSha123", "candidateSha456", "treeSha789",
                120L, "Jenkins reported result FAILED", "...[truncated]\nBUILD FAILURE at the end of the log");
        RemediationReport report = report(ValidationStatus.PASSED, ValidationStatus.PASSED,
                jenkinsOutcome(JenkinsValidationStatus.SUCCESS), withLog);

        String markdown = renderer.render(report);

        assertTrue(markdown.contains("<details>") && markdown.contains("<summary>Full investigation evidence</summary>"),
                markdown);
        int details = markdown.indexOf("<details>");
        int whyNecessary = markdown.indexOf("Why necessary");
        assertTrue(whyNecessary > details, "why-necessary must be inside the collapsible section: " + markdown);
        assertTrue(markdown.contains("the analysis recommended a coordinated bump"), markdown);
        assertTrue(markdown.contains("BUILD FAILURE at the end of the log"),
                "the Jenkins console log excerpt must be surfaced: " + markdown);
    }

    // ---- Bug 2/3: remainingWork -> "Required human checks before merge" + conditional recommended action ---

    @Test
    @DisplayName("a non-empty remainingWork renders a distinct checklist section, one item per bullet, and "
            + "the recommended action says not to merge -- with location-independent wording")
    void remainingWorkRendersChecklistAndBlocksMergeRecommendation() {
        List<String> remainingWork = List.of(
                "Regenerate thirdPartyNotices/index.html.",
                "Perform a real SAML SSO test against an HTTPS IdP.");
        RemediationReport report = report(ValidationStatus.PASSED, ValidationStatus.PASSED,
                null, null, remainingWork, List.of(), Map.of(), FULL_BUILD_COMMAND);

        String markdown = renderer.render(report);

        assertTrue(markdown.contains("## Required human checks before merge"), markdown);
        assertTrue(markdown.contains("- [ ] Regenerate thirdPartyNotices/index.html."), markdown);
        assertTrue(markdown.contains("- [ ] Perform a real SAML SSO test against an HTTPS IdP."), markdown);
        assertTrue(markdown.contains(
                "Do not merge until all required human checks have been completed and reviewed."), markdown);
        assertFalse(markdown.toLowerCase().contains("checks below"),
                "recommended action must be location-independent: " + markdown);
    }

    @Test
    @DisplayName("an empty remainingWork renders no checklist section at all, and the ordinary recommended "
            + "action wording is unchanged")
    void emptyRemainingWorkRendersNoChecklistSection() {
        String markdown = renderer.render(report(ValidationStatus.PASSED, ValidationStatus.PASSED));

        assertFalse(markdown.contains("Required human checks before merge"), markdown);
        assertTrue(markdown.contains("Review and merge if satisfied."), markdown);
    }

    @Test
    @DisplayName("Bug 3 regression: a report with remainingWork never renders the bare unconditional "
            + "\"merge if satisfied\" phrase, whatever the group's risk classification is")
    void remainingWorkNeverRendersUnconditionalMergeRecommendation() {
        RemediationReport report = report(ValidationStatus.PASSED, ValidationStatus.PASSED,
                null, null, List.of("Manually verify the OGNL allowlist still covers every action."),
                List.of(), Map.of(), FULL_BUILD_COMMAND);

        String markdown = renderer.render(report);

        assertFalse(markdown.contains("merge if satisfied"), markdown);
    }

    // ---- Bug 4: planned/controlled dependency changes, distinct from Mend findings ------------------------

    @Test
    @DisplayName("a companion coordinate present only as a plannedChange (no Mend finding of its own) "
            + "appears in Planned / controlled dependency changes but not in Vulnerability findings")
    void companionPlannedChangeAppearsInPlannedSectionNotFindings() {
        PlannedDependencyChange companion = new PlannedDependencyChange(
                "org.apache.httpcomponents.client5:httpclient5-cache", "5.3.1", "5.6.3", "pom.xml",
                PlannedChangeType.VERSION_BUMP, "keeps the cache module in lockstep with httpclient5");
        RemediationReport report = report(ValidationStatus.PASSED, ValidationStatus.PASSED,
                null, null, List.of(), List.of(companion), Map.of(), FULL_BUILD_COMMAND);

        String markdown = renderer.render(report);

        assertTrue(markdown.contains("## Planned / controlled dependency changes"), markdown);
        int plannedSection = markdown.indexOf("Planned / controlled dependency changes");
        int findingsSection = markdown.indexOf("Vulnerability findings");
        assertTrue(markdown.substring(plannedSection).contains("httpclient5-cache"), markdown);
        assertFalse(markdown.substring(findingsSection, plannedSection).contains("httpclient5-cache"), markdown);
    }

    @Test
    @DisplayName("Jackson-shaped fixture: a jackson-databind finding plus a jackson-bom VERSION_BUMP "
            + "planned change renders both sections, with the BOM control point visible")
    void jacksonBomControlPointIsVisibleAlongsideTheFinding() {
        PlannedDependencyChange bomChange = new PlannedDependencyChange(
                "com.fasterxml.jackson:jackson-bom", "2.22.1", "2.22.2", "pom.xml",
                PlannedChangeType.VERSION_BUMP, "raises the imported BOM's own version");
        RemediationReport report = report(ValidationStatus.PASSED, ValidationStatus.PASSED,
                null, null, List.of(), List.of(bomChange), Map.of(), FULL_BUILD_COMMAND);

        String markdown = renderer.render(report);

        assertTrue(markdown.contains("Vulnerability findings"), markdown);
        assertTrue(markdown.contains("com.mchange:c3p0"), markdown);
        assertTrue(markdown.contains("Planned / controlled dependency changes"), markdown);
        assertTrue(markdown.contains("com.fasterxml.jackson:jackson-bom"), markdown);
        assertTrue(markdown.contains("2.22.1"), markdown);
        assertTrue(markdown.contains("2.22.2"), markdown);
        assertTrue(markdown.contains("VERSION_BUMP"), markdown);
    }

    @Test
    @DisplayName("duplicate plannedChanges entries collapse to exactly one row")
    void duplicatePlannedChangesCollapseToOneRow() {
        PlannedDependencyChange change = new PlannedDependencyChange(
                "org.apache.httpcomponents.client5:httpclient5-cache", "5.3.1", "5.6.3", "pom.xml",
                PlannedChangeType.VERSION_BUMP, "keeps the cache module in lockstep with httpclient5");
        RemediationReport report = report(ValidationStatus.PASSED, ValidationStatus.PASSED,
                null, null, List.of(), List.of(change, change), Map.of(), FULL_BUILD_COMMAND);

        String markdown = renderer.render(report);

        int firstIndex = markdown.indexOf("httpclient5-cache");
        int lastIndex = markdown.lastIndexOf("httpclient5-cache");
        assertTrue(firstIndex >= 0, markdown);
        assertTrue(firstIndex == lastIndex, "a duplicate plannedChange must render exactly one row: " + markdown);
    }

    @Test
    @DisplayName("when the dependency-resolution gate confirmed a coordinate's actual resolved version, "
            + "that confirmed version is shown -- not the bare, unconfirmed plan target")
    void confirmedResolvedVersionIsPreferredOverPlanTarget() {
        PlannedDependencyChange change = new PlannedDependencyChange(
                "com.fasterxml.jackson:jackson-bom", "2.22.1", "2.22.2", "pom.xml",
                PlannedChangeType.VERSION_BUMP, "raises the imported BOM's own version");
        RemediationReport report = report(ValidationStatus.PASSED, ValidationStatus.PASSED,
                null, null, List.of(), List.of(change),
                Map.of("com.fasterxml.jackson:jackson-bom", "2.22.2"), FULL_BUILD_COMMAND);

        String markdown = renderer.render(report);

        assertTrue(markdown.contains("2.22.2"), markdown);
    }

    @Test
    @DisplayName("a missing, null or blank confirmed-resolved-version entry safely falls back to the "
            + "plan's own targetVersion -- never rendered as null/blank, and never mislabelled as confirmed")
    void missingOrBlankResolvedVersionFallsBackSafelyToPlanTarget() {
        PlannedDependencyChange change = new PlannedDependencyChange(
                "com.fasterxml.jackson:jackson-bom", "2.22.1", "2.22.2", "pom.xml",
                PlannedChangeType.VERSION_BUMP, "raises the imported BOM's own version");

        String blankEntry = renderer.render(report(ValidationStatus.PASSED, ValidationStatus.PASSED,
                null, null, List.of(), List.of(change),
                Map.of("com.fasterxml.jackson:jackson-bom", ""), FULL_BUILD_COMMAND));
        String missingEntry = renderer.render(report(ValidationStatus.PASSED, ValidationStatus.PASSED,
                null, null, List.of(), List.of(change), Map.of(), FULL_BUILD_COMMAND));

        assertTrue(blankEntry.contains("2.22.2"), blankEntry);
        assertFalse(blankEntry.contains("| com.fasterxml.jackson:jackson-bom | 2.22.1 |  |"), blankEntry);
        assertTrue(missingEntry.contains("2.22.2"), missingEntry);
    }

    @Test
    @DisplayName("no plannedChanges at all renders no Planned / controlled dependency changes section")
    void noPlannedChangesRendersNoSection() {
        String markdown = renderer.render(report(ValidationStatus.PASSED, ValidationStatus.PASSED));

        assertFalse(markdown.contains("Planned / controlled dependency changes"), markdown);
    }

    // ---- Bug 5: itemized lists, never a "; "-joined paragraph -----------------------------------------

    @Test
    @DisplayName("a multi-item What changed renders as separate bullets, never a \"; \"-joined paragraph")
    void multiItemWhatChangedRendersAsSeparateBullets() {
        List<String> items = List.of("Raised com.mchange:c3p0 to 0.14.0.", "Raised mchange-commons-java to 0.6.0.");
        RemediationReport ordinary = report(ValidationStatus.PASSED, ValidationStatus.PASSED);
        RemediationReport report = new RemediationReport(
                ordinary.schemaVersion(), ordinary.commitSha(), ordinary.groupId(), ordinary.memberCoordinates(),
                ordinary.whatChanged(), ordinary.whyNecessary(), ordinary.whyThisRemediation(),
                ordinary.whereChanged(), ordinary.validationPerformed(), ordinary.versionChanges(),
                ordinary.dependencyValidationStatus(), ordinary.fullBuildValidationStatus(), null, null,
                null, null, null, null, null, ordinary.fullBuildValidationCommand(), ordinary.remainingWork(),
                ordinary.plannedChanges(), items, ordinary.validationPerformedItems(),
                ordinary.resolvedVersionsByCoordinates());

        String markdown = renderer.render(report);

        assertTrue(markdown.contains("- Raised com.mchange:c3p0 to 0.14.0.\n"), markdown);
        assertTrue(markdown.contains("- Raised mchange-commons-java to 0.6.0.\n"), markdown);
        assertFalse(markdown.contains("Raised com.mchange:c3p0 to 0.14.0.; Raised"), markdown);
    }

    @Test
    @DisplayName("a single-item What changed still renders as one bullet")
    void singleItemWhatChangedRendersAsOneBullet() {
        String markdown = renderer.render(report(ValidationStatus.PASSED, ValidationStatus.PASSED));

        assertTrue(markdown.contains("- raised c3p0 to 0.14.0\n"), markdown);
    }

    @Test
    @DisplayName("Validation performed renders as bullets, never a \"; \"/\" | \"-joined paragraph")
    void validationPerformedRendersAsBulletsNotAJoinedParagraph() {
        String markdown = renderer.render(report(ValidationStatus.PASSED, ValidationStatus.PASSED));

        assertTrue(markdown.contains("- Dependency-resolution gate: PASSED (ok)\n"), markdown);
        assertTrue(markdown.contains("- Full build (" + FULL_BUILD_COMMAND + "): PASSED (ok)\n"), markdown);
        assertFalse(markdown.contains("Dependency-resolution gate: PASSED (ok) | Full build"), markdown);
    }

    @Test
    @DisplayName("JSON-compatibility guard: the legacy whatChanged/validationPerformed string fields remain "
            + "populated exactly as before, independent of the new structured list fields")
    void legacyStringFieldsRemainPopulatedForJsonCompatibility() {
        RemediationReport report = report(ValidationStatus.PASSED, ValidationStatus.PASSED);

        assertTrue(report.whatChanged().contains("raised c3p0 and mchange-commons-java"), report.whatChanged());
        assertTrue(report.validationPerformed().contains("Dependency-resolution gate: PASSED"),
                report.validationPerformed());
    }

    // ---- Bug 1 (pilot 20260909-061155-6ca4db): each Claude validationPerformed item stays its own bullet -

    @Test
    @DisplayName("multiple Claude validationPerformedItems entries render as separate bullets, never "
            + "re-joined into one \"Claude reported: A; B; C\" bullet")
    void multipleClaudeValidationItemsRenderAsSeparateBullets() {
        RemediationReport ordinary = report(ValidationStatus.PASSED, ValidationStatus.PASSED);
        List<String> validationItems = List.of(
                "Claude: dependency tree resolved cleanly",
                "Claude: reactor tests passed",
                "Claude: packaged WAR contains the expected classes",
                "Dependency-resolution gate: PASSED (ok)",
                "Full build (" + FULL_BUILD_COMMAND + "): PASSED (ok)");
        RemediationReport report = new RemediationReport(
                ordinary.schemaVersion(), ordinary.commitSha(), ordinary.groupId(), ordinary.memberCoordinates(),
                ordinary.whatChanged(), ordinary.whyNecessary(), ordinary.whyThisRemediation(),
                ordinary.whereChanged(), ordinary.validationPerformed(), ordinary.versionChanges(),
                ordinary.dependencyValidationStatus(), ordinary.fullBuildValidationStatus(), null, null,
                null, null, null, null, null, ordinary.fullBuildValidationCommand(), ordinary.remainingWork(),
                ordinary.plannedChanges(), ordinary.whatChangedItems(), validationItems,
                ordinary.resolvedVersionsByCoordinates());

        String markdown = renderer.render(report);

        assertTrue(markdown.contains("- Claude: dependency tree resolved cleanly\n"), markdown);
        assertTrue(markdown.contains("- Claude: reactor tests passed\n"), markdown);
        assertTrue(markdown.contains("- Claude: packaged WAR contains the expected classes\n"), markdown);
        assertFalse(markdown.contains("Claude reported:"), markdown);
        assertFalse(markdown.contains("resolved cleanly; Claude"), markdown);
        assertTrue(markdown.contains("- Dependency-resolution gate: PASSED (ok)\n"), markdown);
        assertTrue(markdown.contains("- Full build (" + FULL_BUILD_COMMAND + "): PASSED (ok)\n"), markdown);
    }

    // ---- Bug 2 (pilot 20260909-061155-6ca4db): OTHER never renders as a second dependency version row ----

    @Test
    @DisplayName("an OTHER planned change for the same coordinate as a VERSION_BUMP renders once in the "
            + "dependency table (as VERSION_BUMP) and once in its own Other planned changes section -- "
            + "never as a second dependency-version row")
    void otherChangeForSameCoordinateRendersInItsOwnSectionNotAsASecondRow() {
        PlannedDependencyChange versionBump = new PlannedDependencyChange(
                "org.apache.httpcomponents.core5:httpcore5", "5.2.5", "5.4.3", "pom.xml",
                PlannedChangeType.VERSION_BUMP, "raises httpcore5 to close the CVE");
        PlannedDependencyChange notice = new PlannedDependencyChange(
                "org.apache.httpcomponents.core5:httpcore5", "5.2.5", "5.4.3", "thirdPartyNotices/index.html",
                PlannedChangeType.OTHER, "regenerate third-party notices metadata for the new version");
        RemediationReport report = report(ValidationStatus.PASSED, ValidationStatus.PASSED,
                null, null, List.of(), List.of(versionBump, notice), Map.of(), FULL_BUILD_COMMAND);

        String markdown = renderer.render(report);

        assertTrue(markdown.contains("## Planned / controlled dependency changes"), markdown);
        assertTrue(markdown.contains("## Other planned changes"), markdown);
        int plannedSection = markdown.indexOf("Planned / controlled dependency changes");
        int otherSection = markdown.indexOf("Other planned changes");
        String plannedTable = markdown.substring(plannedSection, otherSection);
        long rowsForCoordinate = plannedTable.lines()
                .filter(line -> line.contains("httpcore5") && line.startsWith("|")).count();
        assertEquals(1, rowsForCoordinate,
                "httpcore5 must appear exactly once in the dependency table, not once per changeType: "
                        + plannedTable);
        assertFalse(plannedTable.contains("OTHER"), "OTHER must never appear as a dependency-table row: "
                + plannedTable);
        assertTrue(markdown.substring(otherSection).contains("thirdPartyNotices/index.html"), markdown);
        assertTrue(markdown.substring(otherSection).contains("regenerate third-party notices"), markdown);
    }

    @Test
    @DisplayName("four HttpComponents DEPENDENCY_MANAGEMENT_ADDITION entries plus four OTHER notice entries: "
            + "the dependency table has exactly 4 rows, never 8")
    void fourDependencyChangesPlusFourOtherChangesNeverProduceEightDependencyRows() {
        List<PlannedDependencyChange> changes = new java.util.ArrayList<>();
        for (String artifact : List.of("httpcore5", "httpcore5-h2", "httpclient5", "httpclient5-cache")) {
            String coordinates = "org.apache.httpcomponents:" + artifact;
            changes.add(new PlannedDependencyChange(coordinates, "5.2.5", "5.4.3", "pom.xml",
                    PlannedChangeType.DEPENDENCY_MANAGEMENT_ADDITION, "pins " + artifact + " via dependencyManagement"));
            changes.add(new PlannedDependencyChange(coordinates, "5.2.5", "5.4.3", "thirdPartyNotices/index.html",
                    PlannedChangeType.OTHER, "regenerate notices for " + artifact));
        }
        RemediationReport report = report(ValidationStatus.PASSED, ValidationStatus.PASSED,
                null, null, List.of(), changes, Map.of(), FULL_BUILD_COMMAND);

        String markdown = renderer.render(report);

        int plannedSection = markdown.indexOf("Planned / controlled dependency changes");
        int otherSection = markdown.indexOf("Other planned changes");
        String plannedTable = markdown.substring(plannedSection, otherSection);
        long dependencyRows = plannedTable.lines()
                .filter(line -> line.startsWith("| org.apache.httpcomponents:")).count();
        assertEquals(4, dependencyRows, "expected exactly 4 dependency rows, never 8: " + plannedTable);

        String otherContent = markdown.substring(otherSection);
        long otherEntries = otherContent.lines().filter(line -> line.startsWith("- `")).count();
        assertEquals(4, otherEntries, "expected exactly 4 Other planned changes entries: " + otherContent);
    }

    @Test
    @DisplayName("no Other planned changes section is rendered when there is no OTHER-typed entry")
    void noOtherSectionWhenNoOtherEntryExists() {
        PlannedDependencyChange versionBump = new PlannedDependencyChange(
                "com.fasterxml.jackson:jackson-bom", "2.22.1", "2.22.2", "pom.xml",
                PlannedChangeType.VERSION_BUMP, "raises the imported BOM's own version");
        RemediationReport report = report(ValidationStatus.PASSED, ValidationStatus.PASSED,
                null, null, List.of(), List.of(versionBump), Map.of(), FULL_BUILD_COMMAND);

        String markdown = renderer.render(report);

        assertFalse(markdown.contains("Other planned changes"), markdown);
    }
}
