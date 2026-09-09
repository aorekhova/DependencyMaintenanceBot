package com.tungsten.depbot.publication;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Locale;
import java.util.Optional;

/**
 * On Windows, builds a real {@link SSLContext} that trusts exactly the certificates the operating
 * system's own certificate store trusts -- the same root CAs Windows itself uses, including whatever a
 * corporate IT department has installed there (an internal root CA, a TLS-inspecting proxy's certificate,
 * and so on). This is what lets {@code GitLabApiClient} reach a corporate GitLab instance without the
 * {@code PKIX path building failed} error a plain JDK default trust store (which only knows the public
 * CAs bundled with the JDK, not anything Windows-specific) produces on a machine like that -- and without
 * the {@code -Djavax.net.ssl.trustStoreType=Windows-ROOT -Djavax.net.ssl.trustStore=NONE} JVM startup
 * flags this application previously required.
 *
 * <p><strong>This never weakens certificate verification.</strong> It changes which set of trusted roots
 * an ordinary, fully-validating {@link SSLContext} checks against -- from the JDK's bundled public CA
 * list to the Windows certificate store -- and nothing else. There is no trust-all {@code TrustManager},
 * no disabled hostname verification, no {@code --insecure} equivalent anywhere in this class. A
 * certificate that neither the JDK nor Windows trusts is still rejected exactly as before.
 *
 * <p>{@code Windows-ROOT} is a JDK-provided {@link KeyStore} type, backed by the SunMSCAPI provider,
 * available only when the JVM is actually running on Windows. On any other platform (including every CI
 * environment this application's own test suite runs in), {@link #sslContext()} returns {@link
 * Optional#empty()} and {@code GitLabApiClient} falls back to the JDK's ordinary default trust store --
 * exactly today's behaviour off Windows, unchanged.
 */
public final class WindowsTrustStore {

    private WindowsTrustStore() {
    }

    /** Reads the real platform name from the JVM. See {@link #sslContext(String)} for the testable form. */
    public static Optional<SSLContext> sslContext() {
        return sslContext(System.getProperty("os.name", ""));
    }

    /**
     * @param osName {@code System.getProperty("os.name")}'s value, or an equivalent for a test -- kept as
     *               a parameter so this can be exercised for "not Windows" deterministically. The
     *               Windows-only success path can only be exercised for real on a Windows JVM, since
     *               {@code Windows-ROOT} genuinely does not exist anywhere else.
     */
    static Optional<SSLContext> sslContext(String osName) {
        if (osName == null || !osName.toLowerCase(Locale.ROOT).contains("win")) {
            return Optional.empty();
        }
        try {
            KeyStore windowsRoot = KeyStore.getInstance("Windows-ROOT");
            windowsRoot.load(null, null);
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(windowsRoot);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trustManagerFactory.getTrustManagers(), null);
            return Optional.of(context);
        } catch (GeneralSecurityException | IOException | RuntimeException e) {
            // Could not load the Windows certificate store for some reason -- fall back to the JDK's own
            // default trust store rather than guessing at a weaker alternative. This is exactly as safe
            // as this application's own behaviour on a non-Windows platform.
            return Optional.empty();
        }
    }
}
