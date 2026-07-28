package com.tungsten.depbot;

import com.tungsten.depbot.cli.ExitCode;
import com.tungsten.depbot.cli.ScanCommand;
import com.tungsten.depbot.config.EnvConfig;
import com.tungsten.depbot.mend.MendClient;
import com.tungsten.depbot.mend.MendGateway;
import com.tungsten.depbot.report.ConsoleReporter;

import java.net.http.HttpClient;
import java.util.function.Supplier;

/**
 * Command-line entry point.
 *
 * <p>Usage: {@code java -jar dependency-maintenance-bot.jar scan}
 *
 * <p>{@link #run} contains the dispatch logic and returns an {@link ExitCode};
 * {@link #main} is the only place that calls {@code System.exit}. Keeping them apart is what
 * lets tests assert on exit codes without terminating the test JVM.
 */
public final class Main {

    static final String SCAN_COMMAND = "scan";

    private Main() {
    }

    public static void main(String[] args) {
        ConsoleReporter reporter = new ConsoleReporter(System.out, System.err);
        ExitCode code;

        // Throwable, not Exception: without this the JVM would print a full stack trace and
        // exit 1, which both leaks internals and collides with the usage exit code.
        try (HttpClient httpClient = MendClient.defaultHttpClient()) {
            code = run(args, EnvConfig::fromEnvironment, new MendClient(httpClient), reporter);
        } catch (Throwable t) {
            reporter.printUnexpectedError();
            code = ExitCode.UNEXPECTED_ERROR;
        }

        System.exit(code.value());
    }

    /**
     * Validates the command line and delegates to the scan.
     *
     * <p>The reporter passed in must be one that knows no secrets; {@link ScanCommand} derives a
     * seeded reporter itself once configuration has loaded.
     */
    static ExitCode run(String[] args,
                        Supplier<EnvConfig> configSource,
                        MendGateway gateway,
                        ConsoleReporter reporter) {
        if (args == null || args.length != 1 || !SCAN_COMMAND.equals(args[0])) {
            reporter.printUsage();
            return ExitCode.USAGE_ERROR;
        }
        return new ScanCommand(configSource, gateway, reporter).run();
    }
}
