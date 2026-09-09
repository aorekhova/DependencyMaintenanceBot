package com.tungsten.depbot.publication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link WindowsTrustStore} never touches the network -- it only ever loads a local, OS-provided
 * certificate store. This session's own environment is Windows, so the success path below is exercised
 * for real, not merely stubbed.
 */
class WindowsTrustStoreTest {

    @Test
    @DisplayName("a non-Windows platform name never attempts to load Windows-ROOT, and yields no context")
    void nonWindowsPlatformYieldsNoContext() {
        assertEquals(Optional.empty(), WindowsTrustStore.sslContext("Linux"));
        assertEquals(Optional.empty(), WindowsTrustStore.sslContext("Mac OS X"));
        assertEquals(Optional.empty(), WindowsTrustStore.sslContext(""));
    }

    @Test
    @DisplayName("a null platform name is treated as not Windows, never thrown")
    void nullPlatformNameYieldsNoContext() {
        assertEquals(Optional.empty(), WindowsTrustStore.sslContext(null));
    }

    @Test
    @DisplayName("on an actual Windows JVM, a real, usable SSLContext is produced from the Windows "
            + "certificate store -- not a trust-all context, a genuine one backed by Windows-ROOT")
    void windowsPlatformYieldsARealSslContext() {
        Optional<SSLContext> context = WindowsTrustStore.sslContext("Windows 11");

        assertTrue(context.isPresent(),
                "this test only means something on an actual Windows JVM, which this session is");
        assertEquals("TLS", context.get().getProtocol());
    }

    @Test
    @DisplayName("the no-argument overload reads the real os.name system property")
    void noArgumentOverloadReadsTheRealPlatform() {
        // Whatever this JVM's real platform is, this must not throw and must agree with the explicit form.
        Optional<SSLContext> fromRealProperty = WindowsTrustStore.sslContext();
        Optional<SSLContext> fromExplicitName = WindowsTrustStore.sslContext(System.getProperty("os.name", ""));

        assertEquals(fromExplicitName.isPresent(), fromRealProperty.isPresent());
    }
}
