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

import java.util.function.Supplier;

/**
 * Runs one vulnerability scan and decides the resulting exit code.
 *
 * <p>Depends on {@link MendGateway} rather than the concrete HTTP client, so the whole
 * outcome-to-exit-code mapping can be tested with a small fake and no sockets.
 *
 * <p><strong>Reporter ordering is a security control.</strong> The reporter handed in knows no
 * secrets. Configuration problems are reported through it, which is safe because at that point
 * no credential value exists and the message names only the variable. As soon as configuration
 * loads, a seeded reporter is derived and used for everything that follows — including text
 * authored by Mend, which could otherwise echo a credential straight to the console.
 */
public final class ScanCommand {

    private final Supplier<EnvConfig> configSource;
    private final MendGateway gateway;
    private final ConsoleReporter reporter;

    public ScanCommand(Supplier<EnvConfig> configSource,
                       MendGateway gateway,
                       ConsoleReporter reporter) {
        this.configSource = configSource;
        this.gateway = gateway;
        this.reporter = reporter;
    }

    public ExitCode run() {
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
            secureReporter.printReport(counts);
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
        } catch (RuntimeException e) {
            // Last net inside the command, so the injected reporter still handles it and the
            // leak tests can capture the output.
            secureReporter.printUnexpectedError();
            return ExitCode.UNEXPECTED_ERROR;
        }
    }
}
