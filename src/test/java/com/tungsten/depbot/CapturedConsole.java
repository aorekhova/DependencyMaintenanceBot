package com.tungsten.depbot;

import com.tungsten.depbot.report.ConsoleReporter;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

/**
 * A {@link ConsoleReporter} writing into in-memory buffers.
 *
 * <p>Streams are injected rather than swapped globally with {@code System.setOut}, so tests
 * never touch shared mutable state and cannot leak captured output into one another.
 *
 * <p>The charset is pinned to UTF-8 because this machine's console default is Cp1252, which
 * would otherwise make assertions platform-dependent.
 */
public final class CapturedConsole {

    private final ByteArrayOutputStream outBuffer = new ByteArrayOutputStream();
    private final ByteArrayOutputStream errBuffer = new ByteArrayOutputStream();
    private final ConsoleReporter reporter = new ConsoleReporter(
            new PrintStream(outBuffer, true, StandardCharsets.UTF_8),
            new PrintStream(errBuffer, true, StandardCharsets.UTF_8));

    public ConsoleReporter reporter() {
        return reporter;
    }

    public String out() {
        return outBuffer.toString(StandardCharsets.UTF_8);
    }

    public String err() {
        return errBuffer.toString(StandardCharsets.UTF_8);
    }

    public String all() {
        return out() + err();
    }
}
