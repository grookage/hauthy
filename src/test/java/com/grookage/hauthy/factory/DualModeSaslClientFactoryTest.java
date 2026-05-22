package com.grookage.hauthy.factory;

import com.grookage.hauthy.core.DualModeSaslClient;
import lombok.val;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mockStatic;

class DualModeSaslClientFactoryTest {

    private DualModeSaslClientFactory factory;

    @BeforeEach
    void setUp() {
        factory = new DualModeSaslClientFactory();
    }

    @Test
    void getMechanismNamesReturnsGssapiAndIsDefensivelyCopied() {
        val first = factory.getMechanismNames(null);
        val second = factory.getMechanismNames(new HashMap<>());

        assertArrayEquals(new String[]{"GSSAPI"}, first);
        assertNotSame(first, second);

        first[0] = "TAMPERED";
        assertEquals("GSSAPI", factory.getMechanismNames(null)[0]);
    }

    @Test
    void returnsNullWhenGssapiNotInRequestedMechanisms() {
        assertNull(factory.createSaslClient(new String[]{"PLAIN"}, null, "zk", "host", null, null));
        assertNull(factory.createSaslClient(new String[]{"DIGEST-MD5", "CRAM-MD5"}, null, "zk", "host", null, null));
        assertNull(factory.createSaslClient(new String[]{}, null, "zk", "host", null, null));
    }

    @Test
    void returnsNullWhenFallbackDisabledOrUnset() {
        try (MockedStatic<HBaseConfiguration> mock = mockStatic(HBaseConfiguration.class)) {
            val conf = new Configuration(false);
            // hauthy.zk.sasl.fallback not set -> defaults to false
            mock.when(HBaseConfiguration::create).thenReturn(conf);

            assertNull(factory.createSaslClient(new String[]{"GSSAPI"}, null, "zk", "host", null, null));

            // Explicitly false
            conf.setBoolean("hauthy.zk.sasl.fallback", false);
            assertNull(factory.createSaslClient(new String[]{"GSSAPI"}, null, "zk", "host", null, null));
        }
    }

    @Test
    void returnsDualModeSaslClientWhenFallbackEnabled() {
        try (MockedStatic<HBaseConfiguration> mock = mockStatic(HBaseConfiguration.class)) {
            val conf = new Configuration(false);
            conf.setBoolean("hauthy.zk.sasl.fallback", true);
            mock.when(HBaseConfiguration::create).thenReturn(conf);

            val client = factory.createSaslClient(
                    new String[]{"PLAIN", "GSSAPI", "DIGEST-MD5"}, "authz", "zookeeper", "server1", null, null);

            assertNotNull(client);
            assertInstanceOf(DualModeSaslClient.class, client);
            assertEquals("GSSAPI", client.getMechanismName());
        }
    }

    @Test
    void returnsNullGracefullyWhenConfigLoadingFails() {
        try (MockedStatic<HBaseConfiguration> mock = mockStatic(HBaseConfiguration.class)) {
            mock.when(HBaseConfiguration::create).thenThrow(new RuntimeException("classpath borked"));

            assertNull(factory.createSaslClient(new String[]{"GSSAPI"}, null, "zk", "host", null, null));
        }
    }
}
