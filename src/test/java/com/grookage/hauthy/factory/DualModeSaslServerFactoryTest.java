package com.grookage.hauthy.factory;

import com.grookage.hauthy.core.DualModeSaslServer;
import com.grookage.hauthy.core.HauthyConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.security.auth.Subject;
import javax.security.sasl.SaslServer;
import java.util.Arrays;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;

class DualModeSaslServerFactoryTest {

    private DualModeSaslServerFactory factory;

    @BeforeEach
    public void setUp() {
        DualModeSaslServerFactory.reset();
        factory = new DualModeSaslServerFactory();
    }

    @AfterEach
    public void tearDown() {
        DualModeSaslServerFactory.reset();
    }

    @Test
    public void testGetMechanismNames() {
        final var mechanisms = factory.getMechanismNames(null);
        assertNotNull(mechanisms);
        assertEquals(5, mechanisms.length);
        assertArrayEquals(new String[]{"GSSAPI", "PLAIN", "SIMPLE", "ANONYMOUS", "DUAL-MODE"}, mechanisms);
    }

    @Test
    public void testGetMechanismNamesReturnsClone() {
        final var mechanisms1 = factory.getMechanismNames(null);
        final var mechanisms2 = factory.getMechanismNames(null);
        // Should return different array instances
        assertNotSame(mechanisms1, mechanisms2);
        // Modifying one should not affect the other
        mechanisms1[0] = "MODIFIED";
        assertEquals("GSSAPI", mechanisms2[0]);
    }

    @Test
    public void testCreateSaslServerReturnsNullWhenNotEnabled() {
        final var config = HauthyConfig.builder()
                .enabled(false)
                .build();
        DualModeSaslServerFactory.initialize(config, null, null);
        final var server = factory.createSaslServer("GSSAPI", "hbase", "localhost", null, null);
        assertNull(server);
    }

    @Test
    public void testCreateSaslServerReturnsServerWhenEnabled() {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .allowKerberos(true)
                .build();
        DualModeSaslServerFactory.initialize(config, new Subject(), "hbase/localhost@REALM");
        final var server = factory.createSaslServer("GSSAPI", "hbase", "localhost", null, null);
        assertNotNull(server);
        assertInstanceOf(DualModeSaslServer.class, server);
    }

    @Test
    public void testCreateSaslServerWithNullMechanism() {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        DualModeSaslServerFactory.initialize(config, null, null);
        // Null mechanism should be accepted (auto-detect)
        final var server = factory.createSaslServer(null, "hbase", "localhost", null, null);
        assertNotNull(server);
    }

    @Test
    public void testCreateSaslServerWithUnsupportedMechanism() {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        DualModeSaslServerFactory.initialize(config, null, null);
        final var server = factory.createSaslServer("UNSUPPORTED", "hbase", "localhost", null, null);
        assertNull(server);
    }

    @Test
    public void testCreateSaslServerWithAllSupportedMechanisms() {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .allowKerberos(true)
                .build();
        DualModeSaslServerFactory.initialize(config, null, null);
        final String[] mechanisms = {"GSSAPI", "PLAIN", "SIMPLE", "ANONYMOUS", "DUAL-MODE"};
        Arrays.stream(mechanisms).forEach(mechanism -> {
            SaslServer server = factory.createSaslServer(mechanism, "hbase", "localhost", null, null);
            Assertions.assertNotNull(server, "Server should not be null for mechanism: " + mechanism);
        });
    }

    @Test
    public void testCreateSaslServerCaseInsensitiveMechanism() {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        DualModeSaslServerFactory.initialize(config, null, null);
        assertNotNull(factory.createSaslServer("gssapi", "hbase", "localhost", null, null));
        assertNotNull(factory.createSaslServer("Gssapi", "hbase", "localhost", null, null));
        assertNotNull(factory.createSaslServer("GSSAPI", "hbase", "localhost", null, null));
    }

    @Test
    public void testInitializeOnlyOnce() {
        final var config1 = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        final var config2 = HauthyConfig.builder()
                .enabled(false)
                .build();
        DualModeSaslServerFactory.initialize(config1, null, "principal1");
        DualModeSaslServerFactory.initialize(config2, null, "principal2"); // Should be ignored
        final var server = factory.createSaslServer("GSSAPI", "hbase", "localhost", null, null);
        assertNotNull(server);
    }

    @Test
    public void testResetAllowsReinitialization() {
        final var config1 = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        DualModeSaslServerFactory.initialize(config1, null, null);
        assertNotNull(factory.createSaslServer("GSSAPI", "hbase", "localhost", null, null));
        DualModeSaslServerFactory.reset();
        final var config2 = HauthyConfig.builder()
                .enabled(false)
                .build();
        DualModeSaslServerFactory.initialize(config2, null, null);
        // After reset and reinit with disabled config, should return null
        assertNull(factory.createSaslServer("GSSAPI", "hbase", "localhost", null, null));
    }

    @Test
    public void testCreateSaslServerWithoutInitializationUsesDefaultConfig() {
        // Don't initialize - should use default HBaseConfiguration
        final var server = factory.createSaslServer("GSSAPI", "hbase", "localhost", null, null);

        // Default config has enabled=false, so should return null
        assertNull(server);
    }

    @Test
    public void testCreateSaslServerWithProps() {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();
        DualModeSaslServerFactory.initialize(config, null, null);

        final var props = new HashMap<String, String>();
        props.put("javax.security.sasl.qop", "auth");

        final var server = factory.createSaslServer("GSSAPI", "hbase", "localhost", props, null);

        assertNotNull(server);
    }

    @Test
    public void testInitializeWithSubjectAndPrincipal() {
        Subject subject = new Subject();
        String principal = "hbase/server.example.com@EXAMPLE.COM";

        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowKerberos(true)
                .build();
        DualModeSaslServerFactory.initialize(config, subject, principal);
        final var server = factory.createSaslServer("GSSAPI", "hbase", "localhost", null, null);

        assertNotNull(server);
        assertInstanceOf(DualModeSaslServer.class, server);
    }
}

