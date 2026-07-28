package com.tungsten.depbot.report;

import java.io.PrintStream;

/**
 * Every piece of user-facing text this application produces.
 *
 * <p>Concentrating output here makes the "no credentials, no request bodies, no raw responses,
 * no stack traces" rule auditable in one file. All output is plain ASCII, because the Windows
 * console this tool targets reports a Cp1252 encoding and would mangle anything else.
 *
 * <p>Instances are immutable. A reporter starts with no knowledge of any secret; once
 * configuration has loaded, {@link #withSecrets(String...)} derives a <em>new</em> reporter
 * that masks those values. The original is never modified and there is no shared mutable state.
 */
public final class ConsoleReporter {

    public static final String USAGE = "Usage: java -jar dependency-maintenance-bot.jar scan";

    private final PrintStream out;
    private final PrintStream err;
    private final SecretRedactor redactor;

    /** Creates a reporter that knows no secrets yet. */
    public ConsoleReporter(PrintStream out, PrintStream err) {
        this(out, err, SecretRedactor.none());
    }

    private ConsoleReporter(PrintStream out, PrintStream err, SecretRedactor redactor) {
        this.out = out;
        this.err = err;
        this.redactor = redactor;
    }

    /** Returns a new reporter, sharing these streams, that masks the given values. */
    public ConsoleReporter withSecrets(String... secrets) {
        return new ConsoleReporter(out, err, SecretRedactor.of(secrets));
    }

    public void printUsage() {
        writeErr(USAGE);
    }

    public void printConfigError(String safeMessage) {
        writeErr("Configuration error: " + safeMessage);
    }

    public void printReport(SeverityCounts counts) {
        writeOut("Mend vulnerability check completed");
        writeOut("Total vulnerabilities: " + counts.total());
        writeOut("Critical: " + counts.criticalCount());
        writeOut("High: " + counts.highCount());
        writeOut("Medium: " + counts.mediumCount());
        writeOut("Low: " + counts.lowCount());
        writeOut("Other: " + counts.otherCount());
        writeOut("Process result: SUCCESS");
        writeOut("Security result: " + (counts.hasVulnerabilities()
                ? "VULNERABILITIES FOUND"
                : "NO VULNERABILITIES FOUND"));
    }

    /** The message originates from Mend, so redaction is what makes this safe. */
    public void printApiError(int errorCode, String message) {
        writeErr("Mend API error " + errorCode + ": " + message);
    }

    public void printNetworkError(String safeMessage) {
        writeErr("Could not complete the Mend request: " + safeMessage);
    }

    public void printMalformedResponseError() {
        writeErr("Mend returned a response that could not be understood. "
                + "The response content is not shown because it may contain sensitive data.");
    }

    public void printUnexpectedError() {
        writeErr("An unexpected internal error occurred. No details are shown to avoid "
                + "leaking sensitive data.");
    }

    private void writeOut(String text) {
        out.println(redactor.redact(text));
        out.flush();
    }

    private void writeErr(String text) {
        err.println(redactor.redact(text));
        err.flush();
    }
}
