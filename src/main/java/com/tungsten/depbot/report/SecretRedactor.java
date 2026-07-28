package com.tungsten.depbot.report;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Masks known secret values in text that is about to be shown to a user.
 *
 * <p>This exists because some text printed by this application is authored by Mend, not by
 * us: an in-band API error carries an {@code errorMessage} string that could echo a submitted
 * credential back. Keeping credentials out of our own messages is therefore necessary but not
 * sufficient, and this class closes the remaining gap.
 *
 * <p>Instances are immutable.
 */
public final class SecretRedactor {

    public static final String MASK = "***";

    private static final SecretRedactor NONE = new SecretRedactor(List.of());

    private final List<String> secrets;

    private SecretRedactor(List<String> secrets) {
        this.secrets = secrets;
    }

    /** A redactor that knows no secrets and therefore changes nothing. */
    public static SecretRedactor none() {
        return NONE;
    }

    /**
     * Builds a redactor for the given values. {@code null} and blank entries are discarded:
     * masking the empty string would corrupt every message it touched.
     */
    public static SecretRedactor of(String... secrets) {
        if (secrets == null) {
            return NONE;
        }
        List<String> kept = new ArrayList<>();
        for (String secret : secrets) {
            if (secret != null && !secret.isBlank()) {
                kept.add(secret);
            }
        }
        if (kept.isEmpty()) {
            return NONE;
        }
        // Longest first, so that when one credential is a substring of another the longer
        // one is masked before the shorter match could split it.
        kept.sort(Comparator.comparingInt(String::length).reversed());
        return new SecretRedactor(List.copyOf(kept));
    }

    public String redact(String text) {
        if (text == null || text.isEmpty() || secrets.isEmpty()) {
            return text;
        }
        String result = text;
        for (String secret : secrets) {
            result = result.replace(secret, MASK);
        }
        return result;
    }

    /** Deliberately reveals only how many secrets are held, never their values. */
    @Override
    public String toString() {
        return "SecretRedactor[secretCount=" + secrets.size() + "]";
    }
}
