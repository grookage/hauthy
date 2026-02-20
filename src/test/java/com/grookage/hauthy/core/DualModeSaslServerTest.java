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

import com.grookage.hauthy.metrics.AuthMetrics;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.security.sasl.SaslException;
import java.util.Set;

/**
 * Unit tests for {@link DualModeSaslServer}.
 */
class DualModeSaslServerTest {

    @BeforeEach
    void setUp() {
        // Reset metrics before each test
        AuthMetrics.getInstance().reset();
    }

    @Test
    void shouldAllowSimpleAuthWhenEnabled() throws SaslException {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .allowKerberos(true)
                .build();

        final var server = new DualModeSaslServer(config, null, null, null);
        server.setClientAddress("192.168.1.100");

        final var challenge = server.evaluateResponse(new byte[0]);

        Assertions.assertNull(challenge);
        Assertions.assertTrue(server.isComplete());
        Assertions.assertTrue(server.isSimpleMode());
        Assertions.assertEquals(AuthMode.SIMPLE, server.getSelectedAuthMode());
    }

    @Test
    void shouldExtractUsernameFromSimpleAuthResponse() throws SaslException {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .simpleUserMapping(true)
                .build();

        final var server = new DualModeSaslServer(config, null, null, null);
        server.setClientAddress("192.168.1.100");

        final var response = "testuser\0password".getBytes();
        server.evaluateResponse(response);

        Assertions.assertTrue(server.isComplete());
        Assertions.assertEquals("testuser", server.getAuthorizationID());
    }

    @Test
    void shouldUseDefaultUserWhenMappingDisabled() throws SaslException {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .simpleUserMapping(false)
                .simpleDefaultUser("defaultuser")
                .build();

        final var server = new DualModeSaslServer(config, null, null, null);
        server.setClientAddress("192.168.1.100");

        final var response = "testuser\0password".getBytes();
        server.evaluateResponse(response);

        Assertions.assertTrue(server.isComplete());
        Assertions.assertEquals("defaultuser", server.getAuthorizationID());
    }

    @Test
    void shouldRejectSimpleAuthWhenDisabled() {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(false)
                .allowKerberos(true)
                .build();

        final var server = new DualModeSaslServer(config, null, null, null);
        server.setClientAddress("192.168.1.100");

        final var exception = Assertions.assertThrows(SaslException.class,
                () -> server.evaluateResponse(new byte[0]));
        Assertions.assertTrue(exception.getMessage().contains("Simple authentication is disabled"));
    }

    @Test
    void shouldRejectSimpleAuthWhenHostNotAllowed() {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .simpleAllowedHosts(Set.of("10.0.0.*"))
                .build();

        final var server = new DualModeSaslServer(config, null, null, null);
        server.setClientAddress("192.168.1.100");

        final var exception = Assertions.assertThrows(SaslException.class,
                () -> server.evaluateResponse(new byte[0]));
        Assertions.assertTrue(exception.getMessage().contains("not allowed from this host"));
    }

    @Test
    void shouldAllowSimpleAuthWhenHostMatches() throws SaslException {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .simpleAllowedHosts(Set.of("192.168.1.*"))
                .build();

        final var server = new DualModeSaslServer(config, null, null, null);
        server.setClientAddress("192.168.1.100");

        server.evaluateResponse(new byte[0]);

        Assertions.assertTrue(server.isComplete());
    }

    @Test
    void shouldRejectKerberosAuthWhenDisabled() {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .allowKerberos(false)
                .build();

        final var server = new DualModeSaslServer(config, null, null, null);
        server.setClientAddress("192.168.1.100");

        // GSSAPI token starts with 0x60
        final var gssapiToken = new byte[]{0x60, 0x00, 0x00};

        final var exception = Assertions.assertThrows(SaslException.class,
                () -> server.evaluateResponse(gssapiToken));
        Assertions.assertTrue(exception.getMessage().contains("Kerberos authentication is disabled"));
    }

    @Test
    void shouldNotWrapDataInSimpleMode() throws SaslException {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();

        final var server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);

        final var data = "test data".getBytes();
        final var wrapped = server.wrap(data, 0, data.length);

        Assertions.assertArrayEquals(data, wrapped);
    }

    @Test
    void shouldNotUnwrapDataInSimpleMode() throws SaslException {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();

        final var server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);

        final var data = "test data".getBytes();
        final var unwrapped = server.unwrap(data, 0, data.length);

        Assertions.assertArrayEquals(data, unwrapped);
    }

    @Test
    void shouldReturnDualModeBeforeAuth() {
        final var config = HauthyConfig.builder().build();
        final var server = new DualModeSaslServer(config, null, null, null);

        Assertions.assertEquals("DUAL-MODE", server.getMechanismName());
    }

    @Test
    void shouldReturnSimpleMechanismAfterSimpleAuth() throws SaslException {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();

        final var server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);

        Assertions.assertEquals("SIMPLE", server.getMechanismName());
    }

    @Test
    void shouldIncrementSimpleAuthSuccessMetric() throws SaslException {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(true)
                .build();

        final var metrics = AuthMetrics.getInstance();
        final var before = metrics.getSimpleAuthSuccess();

        final var server = new DualModeSaslServer(config, null, null, null);
        server.evaluateResponse(new byte[0]);

        Assertions.assertEquals(before + 1, metrics.getSimpleAuthSuccess());
    }

    @Test
    void shouldIncrementSimpleAuthRejectedMetric() {
        final var config = HauthyConfig.builder()
                .enabled(true)
                .allowSimple(false)
                .allowKerberos(true)
                .build();

        final var metrics = AuthMetrics.getInstance();
        final var before = metrics.getSimpleAuthRejected();

        final var server = new DualModeSaslServer(config, null, null, null);

        try {
            server.evaluateResponse(new byte[0]);
        } catch (SaslException e) {
            // Expected
        }

        Assertions.assertEquals(before + 1, metrics.getSimpleAuthRejected());
    }
}
