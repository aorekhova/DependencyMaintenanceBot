package com.tungsten.depbot.mend;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pure unit tests for transport-failure wording.
 *
 * <p>These exercise the classification directly with constructed exceptions. Two of the four
 * categories cannot be produced deterministically through a real socket — a connect timeout
 * needs an unroutable address, and a refused connection is indistinguishable from a DNS failure
 * — so driving them through the network would be slow and environment-dependent.
 */
class MendErrorClassificationTest {

    @Test
    @DisplayName("a connect timeout is reported as a connection timeout")
    void connectTimeout() {
        assertEquals("the connection to the Mend API timed out",
                MendClient.classify(new HttpConnectTimeoutException("whatever")));
    }

    @Test
    @DisplayName("a request timeout is reported as a request timeout")
    void requestTimeout() {
        assertEquals("the request to the Mend API timed out",
                MendClient.classify(new HttpTimeoutException("whatever")));
    }

    @Test
    @DisplayName("a connect timeout is not misreported as a plain request timeout")
    void connectTimeoutIsNotSwallowedByItsSupertype() {
        // HttpConnectTimeoutException extends HttpTimeoutException, so a wrong ordering here
        // would silently make the specific branch unreachable.
        assertTrue(new HttpConnectTimeoutException("x") instanceof HttpTimeoutException);
        assertFalse(MendClient.classify(new HttpConnectTimeoutException("x"))
                .equals(MendClient.classify(new HttpTimeoutException("x"))));
    }

    @Test
    @DisplayName("a refused connection points at network access and proxy settings")
    void refusedConnection() {
        String message = MendClient.classify(new ConnectException("Connection refused"));
        assertTrue(message.contains("could not reach the Mend API host"));
        assertTrue(message.contains("proxyHost"));
    }

    @Test
    @DisplayName("an unresolvable host gets the same honest wording as a refused connection")
    void unresolvableHost() {
        // Measured: the JDK surfaces DNS failure as ConnectException with a null message,
        // identical to a refusal, so the two must not be claimed apart.
        assertEquals(MendClient.classify(new ConnectException()),
                MendClient.classify(new ConnectException("Connection refused")));
    }

    @Test
    @DisplayName("any other IO failure is reported generically")
    void otherIoFailure() {
        assertEquals("a network error occurred while calling the Mend API",
                MendClient.classify(new SocketException("reset")));
        assertEquals("a network error occurred while calling the Mend API",
                MendClient.classify(new IOException("broken pipe")));
        assertEquals("a network error occurred while calling the Mend API",
                MendClient.classify(new UnknownHostException("nowhere.invalid")));
    }

    @Test
    @DisplayName("no classification ever contains the literal word null")
    void neverContainsNull() {
        IOException[] failures = {
                new HttpConnectTimeoutException("x"),
                new HttpTimeoutException("x"),
                new ConnectException(),          // getMessage() is null on Windows
                new SocketException(),
                new IOException()
        };

        for (IOException failure : failures) {
            String message = MendClient.classify(failure);
            assertFalse(message.contains("null"),
                    "classification leaked a null message for "
                            + failure.getClass().getSimpleName() + ": " + message);
        }
    }
}
