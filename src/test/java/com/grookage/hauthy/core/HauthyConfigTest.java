package com.grookage.hauthy.core;

import lombok.val;
import org.apache.hadoop.conf.Configuration;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

class HauthyConfigTest {

    @Test
    public void testDefaultConfig() {
        val config = HauthyConfig.builder().build();
        assertFalse(config.isEnabled());
        assertTrue(config.isAllowSimple());
        assertTrue(config.isAllowKerberos());
        assertEquals("hbase", config.getSimpleDefaultUser());
        assertTrue(config.isSimpleUserMapping());
        assertTrue(config.isMetricsEnabled());
    }

    @Test
    public void testFromConfiguration() {
        val conf = new Configuration();
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);
        conf.setBoolean(HauthyConfig.ALLOW_SIMPLE, false);
        conf.setBoolean(HauthyConfig.ALLOW_KERBEROS, true);
        conf.set(HauthyConfig.SIMPLE_DEFAULT_USER, "testuser");
        conf.set(HauthyConfig.SIMPLE_ALLOWED_HOSTS, "192.168.1.*,10.0.0.1");

        HauthyConfig config = HauthyConfig.fromConfiguration(conf);

        assertTrue(config.isEnabled());
        assertFalse(config.isAllowSimple());
        assertTrue(config.isAllowKerberos());
        assertEquals("testuser", config.getSimpleDefaultUser());
        assertTrue(config.getSimpleAllowedHosts().contains("192.168.1.*"));
        assertTrue(config.getSimpleAllowedHosts().contains("10.0.0.1"));
    }

    @Test
    public void testFromConfigurationNull() {
        val config = HauthyConfig.fromConfiguration(null);

        assertFalse(config.isEnabled());
        assertTrue(config.isAllowSimple());
    }

    @Test
    public void testFromConfigurationAllowAllHosts() {
        val conf = new Configuration();
        conf.set(HauthyConfig.SIMPLE_ALLOWED_HOSTS, "*");

        val config = HauthyConfig.fromConfiguration(conf);

        assertTrue(config.getSimpleAllowedHosts().isEmpty());
    }

    @Test
    public void testIsSimpleAuthAllowedForHostAllHostsAllowed() {
        val config = HauthyConfig.builder()
                .allowSimple(true)
                .simpleAllowedHosts(new HashSet<>())
                .build();

        assertTrue(config.isSimpleAuthAllowedForHost("192.168.1.100"));
        assertTrue(config.isSimpleAuthAllowedForHost("10.0.0.1"));
        assertTrue(config.isSimpleAuthAllowedForHost("any.host.com"));
    }

    @Test
    public void testIsSimpleAuthAllowedForHostExactMatch() {
        val config = HauthyConfig.builder()
                .allowSimple(true)
                .simpleAllowedHosts(new HashSet<>(Arrays.asList("192.168.1.100", "10.0.0.1")))
                .build();

        assertTrue(config.isSimpleAuthAllowedForHost("192.168.1.100"));
        assertTrue(config.isSimpleAuthAllowedForHost("10.0.0.1"));
        assertFalse(config.isSimpleAuthAllowedForHost("192.168.1.101"));
    }

    @Test
    public void testIsSimpleAuthAllowedForHostWildcardMatch() {
        val config = HauthyConfig.builder()
                .allowSimple(true)
                .simpleAllowedHosts(new HashSet<>(Arrays.asList("192.168.1.*", "10.0.*")))
                .build();

        assertTrue(config.isSimpleAuthAllowedForHost("192.168.1.100"));
        assertTrue(config.isSimpleAuthAllowedForHost("192.168.1.1"));
        assertTrue(config.isSimpleAuthAllowedForHost("10.0.1.1"));
        assertTrue(config.isSimpleAuthAllowedForHost("10.0.255.255"));
        assertFalse(config.isSimpleAuthAllowedForHost("192.168.2.1"));
        assertFalse(config.isSimpleAuthAllowedForHost("11.0.0.1"));
    }

    @Test
    public void testIsSimpleAuthAllowedForHostSimpleDisabled() {
        val config = HauthyConfig.builder()
                .allowSimple(false)
                .build();

        assertFalse(config.isSimpleAuthAllowedForHost("192.168.1.100"));
    }

    @Test
    public void testIsSimpleAuthAllowedForHostNullHost() {
        val config = HauthyConfig.builder()
                .allowSimple(true)
                .simpleAllowedHosts(new HashSet<>(Collections.singletonList("192.168.1.*")))
                .build();

        assertFalse(config.isSimpleAuthAllowedForHost(null));
    }

    @Test
    public void testIsSimpleAuthAllowedForHostLeadingWildcard() {
        val config = HauthyConfig.builder()
                .allowSimple(true)
                .simpleAllowedHosts(new HashSet<>(Collections.singletonList("*.internal.example.com")))
                .build();

        assertTrue(config.isSimpleAuthAllowedForHost("host1.internal.example.com"));
        assertTrue(config.isSimpleAuthAllowedForHost("db.internal.example.com"));
        assertFalse(config.isSimpleAuthAllowedForHost("host1.external.example.com"));
        assertFalse(config.isSimpleAuthAllowedForHost("internal.example.com.evil.org"));
    }

    @Test
    public void testValidateValid() {
        val config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .allowKerberos(true)
                .build();
        assertDoesNotThrow(config::validate);
    }

    @Test
    public void testValidateOnlySimple() {
        val config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .allowKerberos(false)
                .build();
        assertDoesNotThrow(config::validate);
    }

    @Test
    public void testValidateOnlyKerberos() {
        val config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(false)
                .allowKerberos(true)
                .build();
        assertDoesNotThrow(config::validate);
    }

    @Test
    public void testValidateInvalidNoneAllowed() {
        val config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(false)
                .allowKerberos(false)
                .build();
        assertThrows(IllegalStateException.class, config::validate);
    }

    @Test
    public void testValidateDisabledNoneAllowed() {
        val config = HauthyConfig.builder()
                .enabled(false)
                .allowSimple(false)
                .allowKerberos(false)
                .build();
        assertDoesNotThrow(config::validate);
    }
}
