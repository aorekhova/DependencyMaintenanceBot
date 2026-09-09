package com.tungsten.depbot.run;

import java.time.Clock;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Generates the identifier one remediation run is known by.
 *
 * <p>A timestamp plus a short random suffix: readable enough to tell runs apart at a glance, and
 * collision-resistant enough that two runs started in the same second still get distinct ids. Digits and
 * hyphens only, because the run id becomes part of a git branch name and a colon is not valid in one.
 */
public final class RunIds {

    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC);

    private RunIds() {
    }

    public static String generate() {
        return generate(Clock.systemUTC());
    }

    /** @param clock injectable so a test can assert on a predictable prefix */
    public static String generate(Clock clock) {
        String randomSuffix = Long.toHexString(ThreadLocalRandom.current().nextLong() & 0xFFFFFFL);
        return TIMESTAMP.format(clock.instant()) + "-" + randomSuffix;
    }
}
