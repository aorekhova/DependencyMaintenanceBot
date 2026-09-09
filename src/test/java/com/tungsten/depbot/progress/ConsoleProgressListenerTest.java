package com.tungsten.depbot.progress;

import com.tungsten.depbot.CapturedConsole;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConsoleProgressListenerTest {

    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-08-11T04:30:07Z"), ZoneOffset.UTC);

    private final CapturedConsole console = new CapturedConsole();
    private final ConsoleProgressListener listener =
            new ConsoleProgressListener(console.reporter(), FIXED_CLOCK);

    @Test
    @DisplayName("a starting step is announced before it runs, with a timestamp and what it is")
    void startingStepIsAnnouncedUpFront() {
        listener.stepStarting(RemediationStep.ASSESSMENT, "g:a", "read-only investigation");

        String out = console.out();
        assertTrue(out.contains("[04:30:07]"), out);
        assertTrue(out.contains("g:a"), out);
        assertTrue(out.contains("vulnerability analysis"), out);
        assertTrue(out.contains("read-only investigation"), out);
    }

    @Test
    @DisplayName("a finished step reports how long it took, which is what tells slow from stuck")
    void finishedStepReportsElapsedTime() {
        listener.stepStarting(RemediationStep.IMPLEMENTATION, "g:a", null);
        listener.stepFinished(RemediationStep.IMPLEMENTATION, "g:a", "COMPLETED");

        String out = console.out();
        assertTrue(out.contains("implementation done in"), out);
        assertTrue(out.contains("COMPLETED"), out);
    }

    @Test
    @DisplayName("a step finished without a start still reports, rather than losing the line")
    void finishWithoutAStartStillReports() {
        listener.stepFinished(RemediationStep.VALIDATION, "g:a", "PASSED");

        assertTrue(console.out().contains("an unknown time"), console.out());
        assertTrue(console.out().contains("PASSED"), console.out());
    }

    @Test
    @DisplayName("every step has a description, so no step reports as a bare enum name")
    void everyStepHasADescription() {
        for (RemediationStep step : RemediationStep.values()) {
            assertFalse(step.description().isBlank(), step.name());
            assertFalse(step.description().contains("_"),
                    "a description is for a person to read: " + step.description());
        }
    }

    @Test
    @DisplayName("progress goes to stdout, leaving stderr for things that actually went wrong")
    void progressGoesToStandardOutput() {
        listener.stepStarting(RemediationStep.REFRESHING_REFS, "g:a", null);
        listener.stepFinished(RemediationStep.REFRESHING_REFS, "g:a", "up to date");

        assertFalse(console.out().isBlank());
        assertEquals("", console.err());
    }

    @Test
    @DisplayName("elapsed time reads naturally at every scale a real run produces")
    void elapsedTimeIsReadable() {
        assertEquals("0s", ConsoleProgressListener.format(Duration.ofMillis(400)));
        assertEquals("9s", ConsoleProgressListener.format(Duration.ofSeconds(9)));
        assertEquals("1m00s", ConsoleProgressListener.format(Duration.ofSeconds(60)));
        assertEquals("2m36s", ConsoleProgressListener.format(Duration.ofSeconds(156)));
        assertEquals("59m59s", ConsoleProgressListener.format(Duration.ofSeconds(3599)));
        assertEquals("1h04m", ConsoleProgressListener.format(Duration.ofSeconds(3840)));
    }

    @Test
    @DisplayName("the silent listener says nothing at all, heartbeat included")
    void theSilentListenerSaysNothing() {
        RemediationProgressListener none = RemediationProgressListener.none();

        none.stepStarting(RemediationStep.ASSESSMENT, "g:a", "detail");
        none.stepHeartbeat(RemediationStep.ASSESSMENT, "g:a", "detail");
        none.stepFinished(RemediationStep.ASSESSMENT, "g:a", "outcome");

        assertEquals("", console.out());
        assertEquals("", console.err());
    }

    // ---- heartbeat --------------------------------------------------------------------------------

    @Test
    @DisplayName("a heartbeat between start and finish does not erase the start time finish still needs")
    void heartbeatDoesNotEraseTheStartTime() {
        listener.stepStarting(RemediationStep.FULL_BUILD_VALIDATION, "g:a", null);
        listener.stepHeartbeat(RemediationStep.FULL_BUILD_VALIDATION, "g:a", null);
        listener.stepHeartbeat(RemediationStep.FULL_BUILD_VALIDATION, "g:a", null);
        listener.stepFinished(RemediationStep.FULL_BUILD_VALIDATION, "g:a", "PASSED");

        String out = console.out();
        assertEquals(2, out.lines().filter(line -> line.contains("still running")).count(), out);
        assertFalse(out.contains("an unknown time"),
                "stepFinished must still know how long the step actually ran: " + out);
        assertTrue(out.contains("full build validation done in"), out);
    }

    @Test
    @DisplayName("a heartbeat with no preceding start still reports, rather than losing the line")
    void heartbeatWithoutAStartStillReports() {
        listener.stepHeartbeat(RemediationStep.FULL_BUILD_VALIDATION, "g:a", null);

        String out = console.out();
        assertTrue(out.contains("still running"), out);
        assertTrue(out.contains("an unknown time"), out);
    }

    @Test
    @DisplayName("the silent listener's heartbeat needs no override to be safe")
    void nonesHeartbeatIsSafeWithoutOverride() {
        RemediationProgressListener.none().stepHeartbeat(RemediationStep.VALIDATION, "g:a", "detail");
        // No exception, no output -- the interface default is exercised, not an override.
    }
}
