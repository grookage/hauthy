/*
 * Copyright 2026 grookage
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.grookage.hauthy.core;

import org.apache.hadoop.conf.Configuration;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Set;

/**
 * Unit tests for {@link HauthyConfig}.
 */
class HauthyConfigTest {

    @Test
    void shouldReturnDefaultConfigValues() {
        final var config = HauthyConfig.builder().build();

        Assertions.assertFalse(config.isEnabled());
        Assertions.assertTrue(config.isAllowSimple());
        Assertions.assertTrue(config.isAllowKerberos());
        Assertions.assertEquals("hbase", config.getSimpleDefaultUser());
        Assertions.assertTrue(config.isSimpleUserMapping());
        Assertions.assertTrue(config.isMetricsEnabled());
    }

    @Test
    void shouldLoadConfigFromHadoopConfiguration() {
        final var conf = new Configuration();
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);
        conf.setBoolean(HauthyConfig.ALLOW_SIMPLE, false);
        conf.setBoolean(HauthyConfig.ALLOW_KERBEROS, true);
        conf.set(HauthyConfig.SIMPLE_DEFAULT_USER, "testuser");
        conf.set(HauthyConfig.SIMPLE_ALLOWED_HOSTS, "192.168.1.*,10.0.0.1");

        final var config = HauthyConfig.fromConfiguration(conf);

        Assertions.assertTrue(config.isEnabled());
        Assertions.assertFalse(config.isAllowSimple());
        Assertions.assertTrue(config.isAllowKerberos());
        Assertions.assertEquals("testuser", config.getSimpleDefaultUser());
        Assertions.assertTrue(config.getSimpleAllowedHosts().contains("192.168.1.*"));
        Assertions.assertTrue(config.getSimpleAllowedHosts().contains("10.0.0.1"));
    }

    @Test
    void shouldReturnDefaultConfigForNullConfiguration() {
        final var config = HauthyConfig.fromConfiguration(null);

        Assertions.assertFalse(config.isEnabled());
        Assertions.assertTrue(config.isAllowSimple());
    }

    @Test
    void shouldAllowAllHostsWhenWildcardConfigured() {
        final var conf = new Configuration();
        conf.set(HauthyConfig.SIMPLE_ALLOWED_HOSTS, "*");

        final var config = HauthyConfig.fromConfiguration(conf);

        Assertions.assertTrue(config.getSimpleAllowedHosts().isEmpty());
    }

    @Test
    void shouldAllowAllHostsWhenSetIsEmpty() {
        final var config = HauthyConfig.builder()
                .allowSimple(true)
                .simpleAllowedHosts(Set.of())
                .build();

        Assertions.assertTrue(config.isSimpleAuthAllowedForHost("192.168.1.100"));
        Assertions.assertTrue(config.isSimpleAuthAllowedForHost("10.0.0.1"));
        Assertions.assertTrue(config.isSimpleAuthAllowedForHost("any.host.com"));
    }

    @Test
    void shouldMatchExactHostAddress() {
        final var config = HauthyConfig.builder()
                .allowSimple(true)
                .simpleAllowedHosts(Set.of("192.168.1.100", "10.0.0.1"))
                .build();

        Assertions.assertTrue(config.isSimpleAuthAllowedForHost("192.168.1.100"));
        Assertions.assertTrue(config.isSimpleAuthAllowedForHost("10.0.0.1"));
        Assertions.assertFalse(config.isSimpleAuthAllowedForHost("192.168.1.101"));
    }

    @Test
    void shouldMatchWildcardHostPattern() {
        final var config = HauthyConfig.builder()
                .allowSimple(true)
                .simpleAllowedHosts(Set.of("192.168.1.*", "10.0.*"))
                .build();

        Assertions.assertTrue(config.isSimpleAuthAllowedForHost("192.168.1.100"));
        Assertions.assertTrue(config.isSimpleAuthAllowedForHost("192.168.1.1"));
        Assertions.assertTrue(config.isSimpleAuthAllowedForHost("10.0.1.1"));
        Assertions.assertTrue(config.isSimpleAuthAllowedForHost("10.0.255.255"));
        Assertions.assertFalse(config.isSimpleAuthAllowedForHost("192.168.2.1"));
        Assertions.assertFalse(config.isSimpleAuthAllowedForHost("11.0.0.1"));
    }

    @Test
    void shouldRejectAllHostsWhenSimpleDisabled() {
        final var config = HauthyConfig.builder()
                .allowSimple(false)
                .build();

        Assertions.assertFalse(config.isSimpleAuthAllowedForHost("192.168.1.100"));
    }

    @Test
    void shouldRejectNullHost() {
        final var config = HauthyConfig.builder()
                .allowSimple(true)
                .simpleAllowedHosts(Set.of("192.168.1.*"))
                .build();

        Assertions.assertFalse(config.isSimpleAuthAllowedForHost(null));
    }

    @Test
    void shouldValidateWhenBothAuthModesEnabled() {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .allowKerberos(true)
                .build();

        Assertions.assertDoesNotThrow(config::validate);
    }

    @Test
    void shouldValidateWhenOnlySimpleEnabled() {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .allowKerberos(false)
                .build();

        Assertions.assertDoesNotThrow(config::validate);
    }

    @Test
    void shouldValidateWhenOnlyKerberosEnabled() {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(false)
                .allowKerberos(true)
                .build();

        Assertions.assertDoesNotThrow(config::validate);
    }

    @Test
    void shouldThrowWhenNoAuthModeEnabled() {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(false)
                .allowKerberos(false)
                .build();

        final var exception = Assertions.assertThrows(IllegalStateException.class, config::validate);
        Assertions.assertTrue(exception.getMessage().contains("At least one auth mode must be allowed"));
    }

    @Test
    void shouldNotValidateWhenDisabled() {
        final var config = HauthyConfig.builder()
                .enabled(false)
                .allowSimple(false)
                .allowKerberos(false)
                .build();

        Assertions.assertDoesNotThrow(config::validate);
    }
}
