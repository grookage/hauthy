package com.grookage.hauthy.core;

import com.grookage.hauthy.metrics.AuthMetrics;
import lombok.val;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DualModeSaslClientTest {

    private MockedStatic<Security> securityMock;

    @BeforeEach
    void setUp() {
        AuthMetrics.getInstance().reset();
        securityMock = mockStatic(Security.class);
    }

    @AfterEach
    void tearDown() {
        securityMock.close();
    }

    private void givenNoProviders() {
        securityMock.when(() -> Security.getProviders("SaslClientFactory.GSSAPI"))
                .thenReturn(new Provider[0]);
    }

    private void givenProvider(Provider provider) {
        securityMock.when(() -> Security.getProviders("SaslClientFactory.GSSAPI"))
                .thenReturn(new Provider[]{provider});
    }

    private DualModeSaslClient createNoOpClient() {
        givenNoProviders();
        return new DualModeSaslClient(null, "zookeeper", "localhost", null, null);
    }

    private DualModeSaslClient createClientWithMock(SaslClient mockReal) {
        givenProvider(mockProviderReturning(mockReal));
        return new DualModeSaslClient(null, "zookeeper", "localhost", null, null);
    }

    // -- No-op mode tests (no native GSSAPI provider available) --

    @Test
    void skipsHauthyProviderToAvoidRecursion() {
        val hauthyProvider = mock(Provider.class);
        when(hauthyProvider.getName()).thenReturn("Hauthy");

        givenProvider(hauthyProvider);

        // Only Hauthy available -> falls to no-op after SaslException ("no native factory found")
        val client = new DualModeSaslClient(null, "zookeeper", "localhost", null, null);
        assertTrue(client.hasInitialResponse());
    }

    // -- Delegation to real GSSAPI client --

    @SuppressWarnings("unchecked")
    private Provider mockProviderReturning(SaslClient mockClient) {
        val provider = mock(Provider.class);
        when(provider.getName()).thenReturn("SunSASL");

        val service = mock(Provider.Service.class);
        when(provider.getService("SaslClientFactory", "GSSAPI")).thenReturn(service);

        try {
            val mockFactory = mock(javax.security.sasl.SaslClientFactory.class);
            when(mockFactory.createSaslClient(any(), any(), any(), any(), any(), any()))
                    .thenReturn(mockClient);
            when(service.newInstance(null)).thenReturn(mockFactory);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return provider;
    }

    // -- KDC error 7 fallback --

    @Nested
    class NoOpMode {

        @Test
        void entersFallbackWhenNoProviderFound() {
            val client = createNoOpClient();

            assertEquals("GSSAPI", client.getMechanismName());
            assertTrue(client.hasInitialResponse());
            assertFalse(client.isComplete());
        }

        @Test
        void stateTransitions() throws SaslException {
            val client = createNoOpClient();

            // PENDING -> INITIAL_SENT: empty token
            val first = client.evaluateChallenge(new byte[0]);
            assertNotNull(first);
            assertEquals(0, first.length);
            assertTrue(client.isComplete());

            // INITIAL_SENT -> DONE: null (no more tokens)
            assertNull(client.evaluateChallenge(new byte[0]));
            // DONE stays DONE
            assertNull(client.evaluateChallenge(new byte[0]));
        }

        @Test
        void wrapAndUnwrapPassthroughWithOffset() throws SaslException {
            val client = createNoOpClient();
            val data = new byte[]{1, 2, 3, 4, 5};

            assertArrayEquals(new byte[]{2, 3, 4}, client.unwrap(data, 1, 3));
            assertArrayEquals(new byte[]{3, 4, 5}, client.wrap(data, 2, 3));
            // Full array
            assertArrayEquals(data, client.unwrap(data, 0, data.length));
        }

        @Test
        void getNegotiatedPropertyReturnsNull() {
            val client = createNoOpClient();
            assertNull(client.getNegotiatedProperty("javax.security.sasl.qop"));
        }

        @Test
        void disposeIsSafe() {
            val client = createNoOpClient();
            assertDoesNotThrow(client::dispose);
            assertDoesNotThrow(client::dispose); // idempotent
        }
    }

    // -- Provider selection --

    @Nested
    class RealClientDelegation {

        @Test
        void delegatesEvaluateChallengeAndCompletion() throws SaslException {
            val mockReal = mock(SaslClient.class);
            when(mockReal.evaluateChallenge(any())).thenReturn(new byte[]{1, 2, 3});
            when(mockReal.isComplete()).thenReturn(true);
            when(mockReal.hasInitialResponse()).thenReturn(true);

            val client = createClientWithMock(mockReal);

            assertTrue(client.hasInitialResponse());
            assertArrayEquals(new byte[]{1, 2, 3}, client.evaluateChallenge(new byte[]{4, 5}));
            assertTrue(client.isComplete());
        }

        @Test
        void doesNotMarkCompleteUntilRealClientSaysSo() throws SaslException {
            val mockReal = mock(SaslClient.class);
            when(mockReal.evaluateChallenge(any())).thenReturn(new byte[]{1});
            when(mockReal.isComplete()).thenReturn(false);

            val client = createClientWithMock(mockReal);
            client.evaluateChallenge(new byte[0]);

            assertFalse(client.isComplete());
        }

        @Test
        void delegatesWrapUnwrapAndProperties() throws SaslException {
            val mockReal = mock(SaslClient.class);
            when(mockReal.unwrap(any(), anyInt(), anyInt())).thenReturn(new byte[]{42});
            when(mockReal.wrap(any(), anyInt(), anyInt())).thenReturn(new byte[]{99});
            when(mockReal.getNegotiatedProperty("javax.security.sasl.qop")).thenReturn("auth-conf");

            val client = createClientWithMock(mockReal);

            assertArrayEquals(new byte[]{42}, client.unwrap(new byte[]{1, 2}, 0, 2));
            assertArrayEquals(new byte[]{99}, client.wrap(new byte[]{3, 4}, 0, 2));
            assertEquals("auth-conf", client.getNegotiatedProperty("javax.security.sasl.qop"));
        }

        @Test
        void delegatesHasInitialResponse() {
            val mockReal = mock(SaslClient.class);
            when(mockReal.hasInitialResponse()).thenReturn(false);

            val client = createClientWithMock(mockReal);
            assertFalse(client.hasInitialResponse());
        }

        @Test
        void disposeForwardsToRealClient() throws SaslException {
            val mockReal = mock(SaslClient.class);
            val client = createClientWithMock(mockReal);

            client.dispose();
            verify(mockReal).dispose();
        }

        @Test
        void disposeSwallowsExceptionFromRealClient() throws SaslException {
            val mockReal = mock(SaslClient.class);
            doThrow(new SaslException("nope")).when(mockReal).dispose();

            val client = createClientWithMock(mockReal);
            assertDoesNotThrow(client::dispose);
        }
    }

    // -- Helpers --

    @Nested
    class KdcFallback {

        @ParameterizedTest
        @ValueSource(strings = {
                "Server not found in Kerberos database",
                "LOOKING_UP_SERVER",
                "KDC_ERR_S_PRINCIPAL_UNKNOWN"
        })
        void triggersNoOpFallbackOnKnownKdcErrors(String errorMsg) throws SaslException {
            val mockReal = mock(SaslClient.class);
            when(mockReal.evaluateChallenge(any()))
                    .thenThrow(new SaslException("GSS initiate failed", new Exception(errorMsg)));

            val client = createClientWithMock(mockReal);
            val result = client.evaluateChallenge(new byte[0]);

            assertNotNull(result);
            assertEquals(0, result.length);
            assertTrue(client.isComplete());
            verify(mockReal).dispose(); // releases half-initialized GSSContext
        }

        @Test
        void detectsErrorInDeepCauseChain() throws SaslException {
            val root = new Exception("KDC_ERR_S_PRINCIPAL_UNKNOWN");
            val mid = new Exception("inner", root);

            val mockReal = mock(SaslClient.class);
            when(mockReal.evaluateChallenge(any()))
                    .thenThrow(new SaslException("GSS initiate failed", new Exception("outer", mid)));

            val client = createClientWithMock(mockReal);
            val result = client.evaluateChallenge(new byte[0]);

            assertNotNull(result);
            assertEquals(0, result.length);
            assertTrue(client.isComplete());
        }

        @Test
        void recordsFallbackMetric() throws SaslException {
            val mockReal = mock(SaslClient.class);
            when(mockReal.evaluateChallenge(any()))
                    .thenThrow(new SaslException("fail", new Exception("Server not found in Kerberos database")));

            val metrics = AuthMetrics.getInstance();
            val before = metrics.getZkSaslNoOpFallback();

            val client = createClientWithMock(mockReal);
            client.evaluateChallenge(new byte[0]);

            assertEquals(before + 1, metrics.getZkSaslNoOpFallback());
        }

        @ParameterizedTest
        @ValueSource(strings = {"Clock skew too great", "Ticket expired", "Pre-authentication failed"})
        void propagatesNonKdcError7Exceptions(String errorMsg) throws SaslException {
            val mockReal = mock(SaslClient.class);
            when(mockReal.evaluateChallenge(any())).thenThrow(new SaslException(errorMsg));

            val client = createClientWithMock(mockReal);
            val ex = assertThrows(SaslException.class, () -> client.evaluateChallenge(new byte[0]));
            assertTrue(ex.getMessage().contains(errorMsg));
        }
    }
}
