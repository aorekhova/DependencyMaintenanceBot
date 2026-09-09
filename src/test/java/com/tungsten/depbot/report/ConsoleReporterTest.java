package com.tungsten.depbot.report;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConsoleReporterTest {

    private static final String USER_KEY = "USERKEY-DO-NOT-LEAK-9f3a";
    private static final String TOKEN = "TOKEN-DO-NOT-LEAK-7b1c";

    private ByteArrayOutputStream outBuffer;
    private ByteArrayOutputStream errBuffer;
    private ConsoleReporter reporter;

    @BeforeEach
    void setUp() {
        outBuffer = new ByteArrayOutputStream();
        errBuffer = new ByteArrayOutputStream();
        reporter = new ConsoleReporter(
                new PrintStream(outBuffer, true, StandardCharsets.UTF_8),
                new PrintStream(errBuffer, true, StandardCharsets.UTF_8));
    }

    private String out() {
        return outBuffer.toString(StandardCharsets.UTF_8);
    }

    private String err() {
        return errBuffer.toString(StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("usage text is exact and goes to stderr")
    void usageGoesToStderr() {
        reporter.printUsage();
        assertEquals("Usage: java -jar dependency-maintenance-bot.jar "
                        + "<remediate|scan|plan-remediation|prepare-remediation-branches"
                        + "|publish --run <run-id> [--dry-run]>",
                err().strip());
        assertEquals("", out());
    }

    @Test
    @DisplayName("remediation plan summary reports every bucket count")
    void remediationPlanSummary() {
        reporter.printRemediationPlanSummary(1, 2, 3, 4, 5);

        String text = out();
        assertTrue(text.contains("Remediation plan generated"));
        assertTrue(text.contains("Critical libraries: 1"));
        assertTrue(text.contains("High libraries: 2"));
        assertTrue(text.contains("Medium libraries: 3"));
        assertTrue(text.contains("Low libraries: 4"));
        assertTrue(text.contains("Manual analysis required: 5"));
        assertEquals("", err());
    }

    @Test
    @DisplayName("remediation plan locations are printed to stdout")
    void remediationPlanLocations() {
        reporter.printRemediationPlanLocations(
                Path.of("reports", "remediation-plan.json"), Path.of("reports", "remediation-plan.md"));

        String text = out();
        assertTrue(text.contains("remediation-plan.json"));
        assertTrue(text.contains("remediation-plan.md"));
        assertEquals("", err());
    }

    @Test
    @DisplayName("remediation source error goes to stderr")
    void remediationSourceError() {
        reporter.printRemediationSourceError("Could not find reports/mend-actionable-vulnerabilities.json");

        assertTrue(err().contains("Remediation plan error:"));
        assertTrue(err().contains("mend-actionable-vulnerabilities.json"));
        assertEquals("", out());
    }

    @Test
    @DisplayName("the run id is printed to stdout")
    void runIdIsPrinted() {
        reporter.printRunId("20260804-220000-a1b2c3");

        assertTrue(out().contains("Run ID: 20260804-220000-a1b2c3"));
        assertEquals("", err());
    }

    @Test
    @DisplayName("the base commit is printed to stdout")
    void baseCommitIsPrinted() {
        reporter.printBaseCommit("a783793352260d800ae13293ff75f684af38190b");

        assertTrue(out().contains("origin/master"));
        assertTrue(out().contains("a783793352260d800ae13293ff75f684af38190b"));
        assertEquals("", err());
    }

    @Test
    @DisplayName("an empty severity group is reported on stdout, capitalized")
    void severityGroupEmptyIsPrinted() {
        reporter.printSeverityGroupEmpty("medium");

        assertTrue(out().contains("Medium: no libraries, skipped"));
        assertEquals("", err());
    }

    @Test
    @DisplayName("a created branch is reported with its severity and name, and no path")
    void branchCreatedIsPrinted() {
        reporter.printBranchCreated("critical", "remediation/run1/critical");

        String text = out();
        assertTrue(text.contains("Critical:"));
        assertTrue(text.contains("remediation/run1/critical"));
        assertEquals("", err());
    }

    @Test
    @DisplayName("a failed group is reported on stderr, not stdout")
    void severityGroupFailedIsPrinted() {
        reporter.printSeverityGroupFailed("high", "a branch named 'remediation/run1/high' already exists");

        assertTrue(err().contains("High: FAILED"));
        assertTrue(err().contains("already exists"));
        assertEquals("", out());
    }

    @Test
    @DisplayName("a git operation error goes to stderr")
    void gitOperationErrorIsPrinted() {
        reporter.printGitOperationError("\"git fetch origin\" failed (exit 128)");

        assertTrue(err().contains("Git operation error:"));
        assertEquals("", out());
    }

    @Test
    @DisplayName("a dirty checkout error goes to stderr")
    void dirtyCheckoutErrorIsPrinted() {
        reporter.printDirtyCheckoutError("the working tree has uncommitted changes");

        assertTrue(err().contains("Dirty checkout:"));
        assertTrue(err().contains("uncommitted changes"));
        assertEquals("", out());
    }

    @Test
    @DisplayName("an unsafe restore is a loud warning on stderr")
    void restoreWarningIsPrinted() {
        reporter.printRestoreWarning("the checkout at /repo is not clean");

        assertTrue(err().contains("WARNING"));
        assertTrue(err().contains("not clean"));
        assertEquals("", out());
    }

    @Test
    @DisplayName("a run manifest write error goes to stderr")
    void runManifestWriteErrorIsPrinted() {
        reporter.printRunManifestWriteError("Could not write reports/runs/run1/run-manifest.json");

        assertTrue(err().contains("Run manifest write error:"));
        assertEquals("", out());
    }

    @Test
    @DisplayName("the model is named before any unit runs")
    void executionStartNamesTheModel() {
        reporter.printExecutionStarting(3, "opus");

        assertTrue(out().contains("3 unit(s)"));
        assertTrue(out().contains("opus"));
        assertEquals("", err());
    }

    @Test
    @DisplayName("a unit's start and finish are reported to stdout")
    void unitProgressIsPrinted() {
        reporter.printUnitStarting("CRITICAL", "g:a");
        reporter.printUnitFinished("g:a", "COMMITTED_PENDING_VALIDATION");

        assertTrue(out().contains("[CRITICAL] g:a: running"));
        assertTrue(out().contains("g:a: COMMITTED_PENDING_VALIDATION"));
        assertEquals("", err());
    }

    @Test
    @DisplayName("a unit's failure reason goes to stderr, not stdout")
    void unitFailureReasonGoesToStderr() {
        reporter.printUnitFailureReason("g:a", "rolled back -- see attempt.json for details");

        assertTrue(err().contains("g:a: rolled back"));
        assertEquals("", out());
    }

    @Test
    @DisplayName("the execution summary states plainly that no build validation has run")
    void executionSummaryDoesNotOverstateSuccess() {
        reporter.printExecutionSummary(2, 1);

        String text = out();
        assertTrue(text.contains("Units committed (pending validation): 2"));
        assertTrue(text.contains("Units rolled back: 1"));
        assertTrue(text.contains("dependency:tree"), text);
        assertTrue(text.contains("compile"), text);
        assertTrue(text.contains("not something ready to push"), text);
    }

    @Test
    @DisplayName("report with vulnerabilities goes to stdout and says VULNERABILITIES FOUND")
    void reportWithVulnerabilities() {
        reporter.printReport(new SeverityCounts(7, 0, 4, 3, 0, 0));

        String text = out();
        assertTrue(text.contains("Mend vulnerability check completed"));
        assertTrue(text.contains("Total vulnerabilities: 7"));
        assertTrue(text.contains("Critical: 0"));
        assertTrue(text.contains("High: 4"));
        assertTrue(text.contains("Medium: 3"));
        assertTrue(text.contains("Low: 0"));
        assertTrue(text.contains("Other: 0"));
        assertTrue(text.contains("Process result: SUCCESS"));
        assertTrue(text.contains("Security result: VULNERABILITIES FOUND"));
        assertEquals("", err());
    }

    @Test
    @DisplayName("zero-vulnerability report says NO VULNERABILITIES FOUND")
    void reportWithoutVulnerabilities() {
        reporter.printReport(new SeverityCounts(0, 0, 0, 0, 0, 0));

        String text = out();
        assertTrue(text.contains("Total vulnerabilities: 0"));
        assertTrue(text.contains("Security result: NO VULNERABILITIES FOUND"));
        assertFalse(text.contains("Security result: VULNERABILITIES FOUND"));
    }

    @Test
    @DisplayName("process result and security result are separate lines")
    void processAndSecurityResultsAreDistinct() {
        reporter.printReport(new SeverityCounts(1, 1, 0, 0, 0, 0));
        assertTrue(out().lines().anyMatch(line -> line.equals("Process result: SUCCESS")));
        assertTrue(out().lines().anyMatch(line -> line.equals("Security result: VULNERABILITIES FOUND")));
    }

    @Test
    @DisplayName("all error output goes to stderr")
    void errorsGoToStderr() {
        reporter.printConfigError("Missing required environment variable: MEND_USER_KEY");
        reporter.printApiError(1004, "Invalid project token");
        reporter.printNetworkError("request timed out");
        reporter.printMalformedResponseError();
        reporter.printUnexpectedError();

        assertEquals("", out());
        assertTrue(err().contains("MEND_USER_KEY"));
        assertTrue(err().contains("1004"));
        assertTrue(err().contains("request timed out"));
    }

    @Test
    @DisplayName("withSecrets returns a new reporter and leaves the original un-seeded")
    void withSecretsIsImmutable() {
        ConsoleReporter secure = reporter.withSecrets(USER_KEY, TOKEN);
        assertNotSame(reporter, secure);

        // The original still has no secrets, so it does not redact.
        reporter.printApiError(1004, "token " + USER_KEY);
        assertTrue(err().contains(USER_KEY),
                "original reporter must not have been mutated by withSecrets");
    }

    @Test
    @DisplayName("an API error embedding the user key is redacted")
    void apiErrorRedactsUserKey() {
        reporter.withSecrets(USER_KEY, TOKEN)
                .printApiError(1004, "Invalid credentials for user " + USER_KEY);

        assertFalse(err().contains(USER_KEY));
        assertTrue(err().contains(SecretRedactor.MASK));
    }

    @Test
    @DisplayName("an API error embedding the project token is redacted")
    void apiErrorRedactsProjectToken() {
        reporter.withSecrets(USER_KEY, TOKEN)
                .printApiError(1004, "Invalid project token " + TOKEN);

        assertFalse(err().contains(TOKEN));
        assertTrue(err().contains(SecretRedactor.MASK));
    }

    @Test
    @DisplayName("all output is plain ASCII so a Cp1252 console cannot mangle it")
    void allOutputIsAscii() {
        reporter.printUsage();
        reporter.printReport(new SeverityCounts(3, 1, 1, 1, 0, 0));
        reporter.printConfigError("Missing required environment variable: MEND_USER_KEY");
        reporter.printApiError(1004, "Invalid project token");
        reporter.printNetworkError("connection timed out");
        reporter.printMalformedResponseError();
        reporter.printUnexpectedError();
        reporter.printExecutionStarting(2, "opus");
        reporter.printUnitStarting("CRITICAL", "g:a");
        reporter.printUnitFinished("g:a", "COMMITTED_PENDING_VALIDATION");
        reporter.printUnitFailureReason("g:a", "rolled back");
        reporter.printExecutionSummary(1, 1);
        reporter.printRunId("20260804-220000-a1b2c3");
        reporter.printGitOperationError("git fetch failed");
        reporter.printDirtyCheckoutError("uncommitted changes");
        reporter.printRestoreWarning("not clean");
        reporter.printRunManifestWriteError("could not write manifest");

        assertTrue((out() + err()).chars().allMatch(c -> c < 128),
                "reporter emitted a non-ASCII character");
    }

    @Test
    @DisplayName("the remediation run summary reports libraries, groups, commits and both Jenkins gates "
            + "as distinct, separately labelled numbers")
    void remediationRunSummaryReportsDistinctCounts() {
        reporter.printRemediationRunSummary(new RemediationRunSummaryCounts(
                4, 3, 3, 3, 0, 3, 1, 1, 3, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0));

        String text = out();
        assertTrue(text.contains("Libraries remediated: 4"), text);
        assertTrue(text.contains("Automatic remediation groups: 3"), text);
        assertTrue(text.contains("Commits: 3"), text);
        assertTrue(text.contains("Fully validated (committed and built successfully): 3"), text);
        assertTrue(text.contains("Cumulative Jenkins validated groups: 3"), text);
        assertTrue(text.contains("Final integration Jenkins: 1 of 1 cohort(s) succeeded"), text);
        assertTrue(text.contains("Ready to publish (both Jenkins gates succeeded): 3 group(s), 3 commit(s)"), text);
        assertTrue(text.contains("Human Review groups: 1"), text);
        assertTrue(text.contains("Human Review libraries: 2"), text);
    }
}
