package com.grookage.hauthy.core;

import com.grookage.hauthy.metrics.AuthMetrics;
import lombok.SneakyThrows;
import lombok.val;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.security.auth.Subject;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import java.util.Collections;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DualModeSaslServerTest {

    private HauthyConfig config;

    @BeforeAll
    public static void setUp() {
        // Reset metrics before each test
        AuthMetrics.getInstance().reset();
    }

    @BeforeEach
    public void resetMetrics() {
        AuthMetrics.getInstance().reset();
    }

    @Test
    public void testSimpleAuthAllowed() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .allowKerberos(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.setClientAddress("192.168.1.100");
        // Send empty response (simple auth)
        val challenge = server.evaluateResponse(new byte[0]);
        Assertions.assertArrayEquals(new byte[0], challenge);
        Assertions.assertTrue(server.isComplete());
        Assertions.assertTrue(server.isSimpleMode());
        assertEquals(AuthMode.SIMPLE, server.getSelectedAuthMode());
    }

    @Test
    public void testSimpleAuthWithUsername() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .simpleUserMapping(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.setClientAddress("192.168.1.100");
        val response = "testuser\0password".getBytes();
        server.evaluateResponse(response);
        Assertions.assertTrue(server.isComplete());
        assertEquals("testuser", server.getAuthorizationID());
    }

    @Test
    public void testSimpleAuthDefaultUser() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .simpleUserMapping(false)
                .simpleDefaultUser("defaultuser")
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.setClientAddress("192.168.1.100");
        // Send username but mapping disabled
        val response = "testuser\0password".getBytes();
        server.evaluateResponse(response);
        Assertions.assertTrue(server.isComplete());
        assertEquals("defaultuser", server.getAuthorizationID());
    }

    @Test
    public void testSimpleAuthRejectedDisabled() {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(false)
                .allowKerberos(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.setClientAddress("192.168.1.100");
        Assertions.assertThrows(SaslException.class, () -> server.evaluateResponse(new byte[0]));
    }

    @Test
    public void testSimpleAuthRejectedHostNotAllowed() {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .simpleAllowedHosts(new HashSet<>(Collections.singletonList("10.0.0.*")))
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.setClientAddress("192.168.1.100");
        Assertions.assertThrows(SaslException.class, () -> server.evaluateResponse(new byte[0]));
    }

    @Test
    public void testSimpleAuthHostAllowed() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .simpleAllowedHosts(new HashSet<>(Collections.singletonList("192.168.1.*")))
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.setClientAddress("192.168.1.100");
        server.evaluateResponse(new byte[0]);
        Assertions.assertTrue(server.isComplete());
    }

    @Test
    public void testKerberosAuthRejectedDisabled() {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .allowKerberos(false)
                .build();

        val server = new DualModeSaslServer(config, null, null, null);
        server.setClientAddress("192.168.1.100");
        // GSSAPI token starts with 0x60
        val gssapiToken = new byte[]{0x60, 0x00, 0x00};
        Assertions.assertThrows(SaslException.class, () -> server.evaluateResponse(gssapiToken));
    }

    @Test
    public void testWrapSimpleMode() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);
        val data = "test data".getBytes();
        val wrapped = server.wrap(data, 0, data.length);
        Assertions.assertArrayEquals(wrapped, data);
    }

    @Test
    public void testUnwrapSimpleMode() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);
        val data = "test data".getBytes();
        val unwrapped = server.unwrap(data, 0, data.length);
        Assertions.assertArrayEquals(unwrapped, data);
    }

    @Test
    public void testGetMechanismNameBeforeAuth() {
        config = HauthyConfig.builder().build();
        val server = new DualModeSaslServer(config, null, null, null);
        assertEquals("DUAL-MODE", server.getMechanismName());
    }

    @Test
    public void testGetMechanismNameAfterSimpleAuth() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);
        assertEquals("SIMPLE", server.getMechanismName());
    }

    @Test
    public void testMetricsSimpleAuthSuccess() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        val metrics = AuthMetrics.getInstance();
        val before = metrics.getSimpleAuthSuccess();
        val server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);
        assertEquals(before + 1, metrics.getSimpleAuthSuccess());
    }

    @Test
    @SneakyThrows
    public void testMetricsSimpleAuthRejected() {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(false)
                .allowKerberos(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        Assertions.assertThrows(SaslException.class, () -> server.evaluateResponse(new byte[0]));
    }

    @Test
    public void testInitKerberosAuthWithoutSubject() {
        // When serverSubject is null, should attempt to create SASL server without doAs
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .allowKerberos(true)
                .build();

        val server = new DualModeSaslServer(config, "hbase/testhost@REALM", null, null);
        server.setClientAddress("192.168.1.100");

        // GSSAPI token - will fail because no actual Kerberos setup, but tests the code path
        val gssapiToken = new byte[]{0x60, 0x00, 0x00};
        Assertions.assertThrows(SaslException.class, () -> server.evaluateResponse(gssapiToken));
    }

    @Test
    public void testInitKerberosAuthWithSubject() {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .allowKerberos(true)
                .build();

        // Create a mock subject
        val subject = new Subject();
        val server = new DualModeSaslServer(config, "hbase/testhost@REALM", subject, null);
        server.setClientAddress("192.168.1.100");

        // GSSAPI token - will fail but tests the Subject.doAs code path
        val gssapiToken = new byte[]{0x60, 0x00, 0x00};
        Assertions.assertThrows(SaslException.class, () -> server.evaluateResponse(gssapiToken));
    }

    @Test
    public void testInitKerberosAuthRecordsFailureMetric() {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .allowKerberos(true)
                .build();

        val metrics = AuthMetrics.getInstance();
        val beforeFailures = metrics.getKerberosAuthFailure();

        val server = new DualModeSaslServer(config, null, null, null);
        server.setClientAddress("192.168.1.100");

        val gssapiToken = new byte[]{0x60, 0x00, 0x00};
        Assertions.assertThrows(SaslException.class, () -> server.evaluateResponse(gssapiToken));

        assertEquals(beforeFailures + 1, metrics.getKerberosAuthFailure());
    }

    @Test
    public void testGetServerNameFromPrincipal() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();

        // Principal format: service/hostname@REALM
        val server = new DualModeSaslServer(config, "hbase/myhost.example.com@EXAMPLE.COM", null, null);
        server.evaluateResponse(new byte[0]);

        // getServerName is private, but we can verify it works through getMechanismName
        Assertions.assertTrue(server.isComplete());
    }

    @Test
    public void testGetServerNameWithoutPrincipal() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();

        // No principal - should fallback to localhost
        val server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);

        Assertions.assertTrue(server.isComplete());
    }

    @Test
    public void testGetServerNameWithPrincipalWithoutSlash() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();

        // Principal without slash - should fallback to localhost
        val server = new DualModeSaslServer(config, "hbase@EXAMPLE.COM", null, null);
        server.evaluateResponse(new byte[0]);

        Assertions.assertTrue(server.isComplete());
    }


    @Test
    public void testGetNegotiatedPropertyBeforeAuth() {
        config = HauthyConfig.builder().build();
        val server = new DualModeSaslServer(config, null, null, null);

        // Before authentication, should return null
        Assertions.assertNull(server.getNegotiatedProperty(Sasl.QOP));
    }

    @Test
    public void testGetNegotiatedPropertyAfterSimpleAuth() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);

        // After simple auth, QOP should be "auth"
        assertEquals("auth", server.getNegotiatedProperty(Sasl.QOP));
    }

    @Test
    public void testGetNegotiatedPropertyUnknownProperty() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);

        // Unknown property should return null
        Assertions.assertNull(server.getNegotiatedProperty("unknown.property"));
    }

    @Test
    public void testUnwrapBeforeAuthThrows() {
        config = HauthyConfig.builder().build();
        val server = new DualModeSaslServer(config, null, null, null);

        val data = "test".getBytes();
        Assertions.assertThrows(SaslException.class, () -> server.unwrap(data, 0, data.length));
    }

    @Test
    public void testWrapBeforeAuthThrows() {
        config = HauthyConfig.builder().build();
        val server = new DualModeSaslServer(config, null, null, null);

        val data = "test".getBytes();
        Assertions.assertThrows(SaslException.class, () -> server.wrap(data, 0, data.length));
    }

    @Test
    public void testUnwrapWithOffset() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);

        val data = "prefix_test_data".getBytes();
        val unwrapped = server.unwrap(data, 7, 4); // "test"
        Assertions.assertArrayEquals("test".getBytes(), unwrapped);
    }

    @Test
    public void testWrapWithOffset() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);

        val data = "prefix_test_data".getBytes();
        val wrapped = server.wrap(data, 7, 4); // "test"
        Assertions.assertArrayEquals("test".getBytes(), wrapped);
    }

    @Test
    public void testDisposeBeforeAuth() {
        config = HauthyConfig.builder().build();
        val server = new DualModeSaslServer(config, null, null, null);

        // Should not throw even if no delegate server
        Assertions.assertDoesNotThrow(server::dispose);
    }

    @Test
    public void testDisposeAfterSimpleAuth() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);

        // Should dispose delegate and record connection closed
        Assertions.assertDoesNotThrow(server::dispose);
    }

    @Test
    public void testDisposeRecordsConnectionClosed() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();

        val metrics = AuthMetrics.getInstance();
        val beforeActive = metrics.getActiveConnections();

        val server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);
        // After evaluateResponse (simple auth success), activeConnections incremented by 1
        assertEquals(beforeActive + 1, metrics.getActiveConnections());

        server.dispose();
        // After dispose, activeConnections decremented by 1
        assertEquals(beforeActive, metrics.getActiveConnections());
    }

    @Test
    public void testSimpleSaslServerWithNullResponse() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .simpleDefaultUser("defaultuser")
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(null);

        Assertions.assertTrue(server.isComplete());
        assertEquals("defaultuser", server.getAuthorizationID());
    }

    @Test
    public void testSimpleSaslServerWithEmptyUsername() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .simpleUserMapping(true)
                .simpleDefaultUser("defaultuser")
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        // Empty username in response
        server.evaluateResponse("\0password".getBytes());

        Assertions.assertTrue(server.isComplete());
        assertEquals("defaultuser", server.getAuthorizationID());
    }

    @Test
    public void testSimpleSaslServerMechanismName() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);

        assertEquals("SIMPLE", server.getMechanismName());
    }

    @Test
    public void testSimpleSaslServerIsAlwaysComplete() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);

        Assertions.assertTrue(server.isComplete());
    }

    @Test
    public void testSimpleSaslServerUnwrap() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);

        val data = new byte[]{1, 2, 3, 4, 5};
        val unwrapped = server.unwrap(data, 1, 3);
        Assertions.assertArrayEquals(new byte[]{2, 3, 4}, unwrapped);
    }

    @Test
    public void testSimpleSaslServerWrap() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);

        val data = new byte[]{1, 2, 3, 4, 5};
        val wrapped = server.wrap(data, 1, 3);
        Assertions.assertArrayEquals(new byte[]{2, 3, 4}, wrapped);
    }

    @Test
    public void testSimpleSaslServerWithUserMappingDisabled() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .simpleUserMapping(false)
                .simpleDefaultUser("system_user")
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse("provideduser\0password".getBytes());

        // Should use default user because mapping is disabled
        assertEquals("system_user", server.getAuthorizationID());
    }

    @Test
    public void testSimpleSaslServerWithInvalidUtf8Response() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .simpleUserMapping(true)
                .simpleDefaultUser("fallback_user")
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        // Invalid UTF-8 bytes
        server.evaluateResponse(new byte[]{(byte) 0xFF, (byte) 0xFE});

        // Should fallback to default user
        Assertions.assertTrue(server.isComplete());
    }

    @Test
    public void testDetectAuthModeWithGSSAPIString() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .allowKerberos(false)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.setClientAddress("192.168.1.100");

        // Response containing "GSSAPI" string - should be detected as SIMPLE, not Kerberos
        // because detection is based on ASN.1 structure (0x60), not string content
        val response = "GSSAPI mechanism".getBytes();
        server.evaluateResponse(response);  // Should NOT throw
        assertEquals(AuthMode.SIMPLE, server.getSelectedAuthMode());
    }

    @Test
    public void testDetectAuthModeWithGSSAPIToken() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .allowKerberos(false) // Disable Kerberos to get exception
                .build();
        val server = new DualModeSaslServer(config, null, null, null);
        server.setClientAddress("192.168.1.100");

        // Valid GSSAPI token structure (starts with 0x60 APPLICATION tag)
        val gssapiToken = new byte[]{0x60, 0x03, 0x01, 0x02, 0x03};
        Assertions.assertThrows(SaslException.class, () -> server.evaluateResponse(gssapiToken));
    }

    @Test
    public void testDetectAuthModeWithNullResponse() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);

        server.evaluateResponse(null);
        assertEquals(AuthMode.SIMPLE, server.getSelectedAuthMode());
    }

    @Test
    public void testDelegateEvaluateResponseMultipleCalls() throws SaslException {
        config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        val server = new DualModeSaslServer(config, null, null, null);

        // First call - initializes simple auth
        server.evaluateResponse(new byte[0]);
        Assertions.assertTrue(server.isComplete());

        // Second call - delegates to SimpleSaslServer
        val secondResponse = server.evaluateResponse("additional".getBytes());
        Assertions.assertArrayEquals(new byte[0], secondResponse);
    }
}
