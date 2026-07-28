package com.tungsten.depbot.cli;

/**
 * Every process outcome this CLI can produce, with the integer status it returns.
 *
 * <p>Exit code {@code 0} means the scan ran to completion. It does <em>not</em> mean the
 * project is free of vulnerabilities; the security verdict is reported separately on the
 * console. CI gating on severity is deliberately out of scope for this slice.
 */
public enum ExitCode {

    SUCCESS(0),
    USAGE_ERROR(1),
    CONFIG_ERROR(2),
    API_ERROR(3),
    NETWORK_ERROR(4),
    MALFORMED_RESPONSE(5),
    UNEXPECTED_ERROR(70);

    private final int value;

    ExitCode(int value) {
        this.value = value;
    }

    public int value() {
        return value;
    }
}
