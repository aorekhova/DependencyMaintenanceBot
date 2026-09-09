package com.tungsten.depbot.cli;

import com.tungsten.depbot.config.ConfigurationException;
import com.tungsten.depbot.config.EnvConfig;
import com.tungsten.depbot.mend.MalformedResponseException;
import com.tungsten.depbot.mend.MendApiException;
import com.tungsten.depbot.mend.MendGateway;
import com.tungsten.depbot.mend.MendHttpException;
import com.tungsten.depbot.mend.model.VulnerabilityReport;
import com.tungsten.depbot.report.ConsoleReporter;
import com.tungsten.depbot.report.SeverityCounts;
import com.tungsten.depbot.report.actionable.ActionableReportService;
import com.tungsten.depbot.report.actionable.ReportWriteException;
import com.tungsten.depbot.report.actionable.WrittenReports;

import java.util.function.Supplier;

/**
 * Runs one vulnerability scan and decides the resulting exit code.
 *
 * <p>Depends on {@link MendGateway} rather than the concrete HTTP client, so the whole
 * outcome-to-exit-code mapping can be tested with a small fake and no sockets.
 *
 * <p><strong>Two orderings in {@link #run()} are deliberate.</strong>
 *
 * <p>First, the previous report pair is invalidated before anything else — before credentials are
 * read and before Mend is contacted. The report filenames are fixed, so a stale file at a known path
 * is indistinguishable from a fresh one; removing it up front means absence reliably signals that the
 * last scan did not succeed. The cost is real and accepted: a scan that fails on a missing
 * environment variable also destroys yesterday's report. Absence is an unambiguous signal, staleness
 * is not. If invalidation itself fails the scan stops immediately, because the contract can no longer
 * be honoured and there is no point calling Mend.
 *
 * <p>Second, the reporter handed in knows no secrets. Configuration problems are reported through it,
 * which is safe because at that point no credential value exists and the message names only the
 * variable. As soon as configuration loads, a seeded reporter is derived and used for everything that
 * follows — including text authored by Mend, which could otherwise echo a credential to the console.
 */
public final class ScanCommand {

    private final Supplier<EnvConfig> configSource;
    private final MendGateway gateway;
    private final ConsoleReporter reporter;
    private final ActionableReportService reportService;

    public ScanCommand(Supplier<EnvConfig> configSource,
                       MendGateway gateway,
                       ConsoleReporter reporter,
                       ActionableReportService reportService) {
        this.configSource = configSource;
        this.gateway = gateway;
        this.reporter = reporter;
        this.reportService = reportService;
    }

    public ExitCode run() {
        try {
            reportService.invalidatePreviousReports();
        } catch (ReportWriteException e) {
            return reportWriteFailure(reporter, e);
        }

        EnvConfig config;
        try {
            config = configSource.get();
        } catch (ConfigurationException e) {
            reporter.printConfigError(e.getMessage());
            return ExitCode.CONFIG_ERROR;
        } catch (RuntimeException e) {
            reporter.printUnexpectedError();
            return ExitCode.UNEXPECTED_ERROR;
        }

        ConsoleReporter secureReporter =
                reporter.withSecrets(config.userKey(), config.projectToken());

        try {
            VulnerabilityReport report = gateway.fetchVulnerabilityReport(config);
            SeverityCounts counts = SeverityCounts.from(report.vulnerabilities());

            // The summary is printed first, so an operator keeps the scan's primary value even if
            // writing the detailed report then fails.
            secureReporter.printReport(counts);

            WrittenReports written = reportService
                    .withSecrets(config.userKey(), config.projectToken())
                    .generate(report.vulnerabilities(), counts);
            secureReporter.printReportLocations(written.jsonPath(), written.markdownPath());

            return ExitCode.SUCCESS;
        } catch (MendApiException e) {
            secureReporter.printApiError(e.errorCode(), e.getMessage());
            return ExitCode.API_ERROR;
        } catch (MalformedResponseException e) {
            secureReporter.printMalformedResponseError();
            return ExitCode.MALFORMED_RESPONSE;
        } catch (MendHttpException e) {
            secureReporter.printNetworkError(e.getMessage());
            return ExitCode.NETWORK_ERROR;
        } catch (ReportWriteException e) {
            return reportWriteFailure(secureReporter, e);
        } catch (RuntimeException e) {
            // Last net inside the command, so the injected reporter still handles it and the leak
            // tests can capture the output.
            secureReporter.printUnexpectedError();
            return ExitCode.UNEXPECTED_ERROR;
        }
    }

    /**
     * Chooses between the two write-failure messages. They ask different things of the operator:
     * one means retry, the other means inspect the directory before trusting anything in it.
     */
    private static ExitCode reportWriteFailure(ConsoleReporter reporter, ReportWriteException e) {
        if (e.pairStateGuaranteed()) {
            reporter.printReportWriteError(e.getMessage());
        } else {
            reporter.printReportPairStateUnknown(e.getMessage(), e.unreconciledPaths());
        }
        return ExitCode.REPORT_WRITE_ERROR;
    }
}
