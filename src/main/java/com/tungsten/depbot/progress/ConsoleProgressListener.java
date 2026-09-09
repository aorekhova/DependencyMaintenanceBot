package com.tungsten.depbot.progress;

import com.tungsten.depbot.report.ConsoleReporter;

import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * Prints live progress through {@link ConsoleReporter}, timestamped, with how long each step took.
 *
 * <p>Goes through the reporter rather than writing to a stream directly, so that every piece of
 * user-facing text this application produces still comes out of one auditable place.
 *
 * <p>Elapsed time is measured with {@link System#nanoTime()} rather than the clock: it is a duration, and a
 * wall clock that steps -- over a daylight-saving boundary, or an NTP correction during a long Claude call
 * -- would report a wrong one. The clock is used only for the timestamps that label each line.
 */
public final class ConsoleProgressListener implements RemediationProgressListener {

    private static final DateTimeFormatter TIME_OF_DAY =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneOffset.UTC);

    private final ConsoleReporter reporter;
    private final Clock clock;
    private final Map<RemediationStep, Long> startedAt = new EnumMap<>(RemediationStep.class);

    public ConsoleProgressListener(ConsoleReporter reporter, Clock clock) {
        this.reporter = Objects.requireNonNull(reporter, "reporter");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public void stepStarting(RemediationStep step, String coordinates, String detail) {
        startedAt.put(step, System.nanoTime());
        reporter.printStepStarting(now(), coordinates, step.description(), detail);
    }

    @Override
    public void stepFinished(RemediationStep step, String coordinates, String outcome) {
        Long started = startedAt.remove(step);
        String elapsed = started == null
                ? "an unknown time"
                : format(Duration.ofNanos(System.nanoTime() - started));
        reporter.printStepFinished(now(), coordinates, step.description(), elapsed, outcome);
    }

    @Override
    public void stepHeartbeat(RemediationStep step, String coordinates, String detail) {
        // get, not remove: stepFinished still needs this entry to compute the real elapsed time.
        Long started = startedAt.get(step);
        String elapsed = started == null
                ? "an unknown time"
                : format(Duration.ofNanos(System.nanoTime() - started));
        reporter.printStepHeartbeat(now(), coordinates, step.description(), elapsed, detail);
    }

    private String now() {
        return TIME_OF_DAY.format(clock.instant());
    }

    /** Short and readable at a glance: {@code 4s}, {@code 2m36s}, {@code 1h04m}. */
    static String format(Duration elapsed) {
        long seconds = Math.max(0, elapsed.toSeconds());
        if (seconds < 60) {
            return seconds + "s";
        }
        if (seconds < 3600) {
            return (seconds / 60) + "m" + String.format("%02ds", seconds % 60);
        }
        return (seconds / 3600) + "h" + String.format("%02dm", (seconds % 3600) / 60);
    }
}
