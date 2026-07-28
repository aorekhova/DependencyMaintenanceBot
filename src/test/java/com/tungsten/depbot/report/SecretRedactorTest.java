package com.tungsten.depbot.report;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecretRedactorTest {

    private static final String USER_KEY = "USERKEY-DO-NOT-LEAK-9f3a";
    private static final String TOKEN = "TOKEN-DO-NOT-LEAK-7b1c";

    @Test
    @DisplayName("none() leaves text untouched")
    void noneLeavesTextUntouched() {
        assertEquals("hello " + USER_KEY, SecretRedactor.none().redact("hello " + USER_KEY));
    }

    @Test
    @DisplayName("a single secret is masked")
    void singleSecretIsMasked() {
        String redacted = SecretRedactor.of(USER_KEY).redact("key is " + USER_KEY + " ok");
        assertEquals("key is " + SecretRedactor.MASK + " ok", redacted);
    }

    @Test
    @DisplayName("both credentials are masked when both appear")
    void bothCredentialsAreMasked() {
        String redacted = SecretRedactor.of(USER_KEY, TOKEN)
                .redact("user=" + USER_KEY + " token=" + TOKEN);
        assertFalse(redacted.contains(USER_KEY));
        assertFalse(redacted.contains(TOKEN));
        assertEquals("user=*** token=***", redacted);
    }

    @Test
    @DisplayName("a secret that is a substring of another is still fully masked")
    void substringSecretIsFullyMasked() {
        String shortSecret = "abc123";
        String longSecret = "abc123def456";
        String redacted = SecretRedactor.of(shortSecret, longSecret)
                .redact("long=" + longSecret + " short=" + shortSecret);

        // Without longest-first ordering the long value would be partially masked
        // as "***def456", leaving half the credential visible.
        assertFalse(redacted.contains("def456"), "long secret leaked a fragment: " + redacted);
        assertEquals("long=*** short=***", redacted);
    }

    @Test
    @DisplayName("null and blank secrets are ignored rather than masking everything")
    void blankSecretsAreIgnored() {
        SecretRedactor redactor = SecretRedactor.of(null, "", "   ");
        assertEquals("untouched text", redactor.redact("untouched text"));
    }

    @Test
    @DisplayName("of(null) yields a no-op redactor")
    void nullArrayYieldsNoOp() {
        assertEquals("untouched", SecretRedactor.of((String[]) null).redact("untouched"));
    }

    @Test
    @DisplayName("redact(null) returns null")
    void redactNullReturnsNull() {
        assertNull(SecretRedactor.of(USER_KEY).redact(null));
    }

    @Test
    @DisplayName("toString never reveals the secret values")
    void toStringDoesNotRevealSecrets() {
        String text = SecretRedactor.of(USER_KEY, TOKEN).toString();
        assertFalse(text.contains(USER_KEY));
        assertFalse(text.contains(TOKEN));
        assertTrue(text.contains("secretCount=2"));
    }
}
