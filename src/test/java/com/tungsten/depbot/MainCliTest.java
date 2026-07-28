package com.tungsten.depbot;

import com.tungsten.depbot.cli.ExitCode;
import com.tungsten.depbot.config.EnvConfig;
import com.tungsten.depbot.mend.MendGateway;
import com.tungsten.depbot.mend.model.VulnerabilityReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MainCliTest {

    private static final EnvConfig CONFIG =
            new EnvConfig("USERKEY-DO-NOT-LEAK-9f3a", "TOKEN-DO-NOT-LEAK-7b1c");

    private static final MendGateway EMPTY_REPORT =
            config -> new VulnerabilityReport(List.of());

    private ExitCode runWith(CapturedConsole console, String... args) {
        return Main.run(args, () -> CONFIG, EMPTY_REPORT, console.reporter());
    }

    @Test
    @DisplayName("scan reaches the scan path and succeeds")
    void scanRunsTheCheck() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.SUCCESS, runWith(console, "scan"));
        assertTrue(console.out().contains("Mend vulnerability check completed"));
    }

    @Test
    @DisplayName("no argument prints usage to stderr and returns USAGE_ERROR")
    void noArgument() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR, runWith(console));

        assertTrue(console.err().contains("Usage: java -jar dependency-maintenance-bot.jar scan"));
        assertEquals("", console.out());
    }

    @Test
    @DisplayName("an unknown argument prints usage and returns USAGE_ERROR")
    void unknownArgument() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR, runWith(console, "bogus"));
        assertTrue(console.err().contains("Usage:"));
    }

    @Test
    @DisplayName("extra arguments after scan are rejected")
    void extraArguments() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR, runWith(console, "scan", "extra"));
        assertFalse(console.out().contains("Mend vulnerability check completed"));
    }

    @Test
    @DisplayName("command matching is exact and case-sensitive")
    void commandMatchingIsExact() {
        assertEquals(ExitCode.USAGE_ERROR, runWith(new CapturedConsole(), "SCAN"));
        assertEquals(ExitCode.USAGE_ERROR, runWith(new CapturedConsole(), "Scan"));
        assertEquals(ExitCode.USAGE_ERROR, runWith(new CapturedConsole(), " scan"));
    }

    @Test
    @DisplayName("a null argument array is treated as a usage error")
    void nullArguments() {
        CapturedConsole console = new CapturedConsole();
        assertEquals(ExitCode.USAGE_ERROR,
                Main.run(null, () -> CONFIG, EMPTY_REPORT, console.reporter()));
    }

    @Test
    @DisplayName("exit codes have the documented numeric values")
    void exitCodeValues() {
        assertEquals(0, ExitCode.SUCCESS.value());
        assertEquals(1, ExitCode.USAGE_ERROR.value());
        assertEquals(2, ExitCode.CONFIG_ERROR.value());
        assertEquals(3, ExitCode.API_ERROR.value());
        assertEquals(4, ExitCode.NETWORK_ERROR.value());
        assertEquals(5, ExitCode.MALFORMED_RESPONSE.value());
        assertEquals(70, ExitCode.UNEXPECTED_ERROR.value());
    }
}
