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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AuthMode}.
 */
class AuthModeTest {

    @Test
    void shouldReturnKerberosForGssapiMechanism() {
        Assertions.assertEquals(AuthMode.KERBEROS, AuthMode.fromMechanism("GSSAPI"));
        Assertions.assertEquals(AuthMode.KERBEROS, AuthMode.fromMechanism("gssapi"));
    }

    @Test
    void shouldReturnSimpleForSimpleAndPlainMechanisms() {
        Assertions.assertEquals(AuthMode.SIMPLE, AuthMode.fromMechanism("SIMPLE"));
        Assertions.assertEquals(AuthMode.SIMPLE, AuthMode.fromMechanism("PLAIN"));
        Assertions.assertEquals(AuthMode.SIMPLE, AuthMode.fromMechanism("plain"));
    }

    @Test
    void shouldReturnAnonymousForAnonymousMechanism() {
        Assertions.assertEquals(AuthMode.ANONYMOUS, AuthMode.fromMechanism("ANONYMOUS"));
    }

    @Test
    void shouldReturnSimpleForNullMechanism() {
        Assertions.assertEquals(AuthMode.SIMPLE, AuthMode.fromMechanism(null));
    }

    @Test
    void shouldReturnSimpleForUnknownMechanism() {
        Assertions.assertEquals(AuthMode.SIMPLE, AuthMode.fromMechanism("UNKNOWN"));
        Assertions.assertEquals(AuthMode.SIMPLE, AuthMode.fromMechanism(""));
    }

    @Test
    void shouldReturnCorrectSecureStatus() {
        Assertions.assertTrue(AuthMode.KERBEROS.isSecure());
        Assertions.assertFalse(AuthMode.SIMPLE.isSecure());
        Assertions.assertFalse(AuthMode.ANONYMOUS.isSecure());
    }

    @Test
    void shouldReturnCorrectKerberosRequirement() {
        Assertions.assertTrue(AuthMode.KERBEROS.requiresKerberos());
        Assertions.assertFalse(AuthMode.SIMPLE.requiresKerberos());
        Assertions.assertFalse(AuthMode.ANONYMOUS.requiresKerberos());
    }

    @Test
    void shouldReturnCorrectSaslMechanism() {
        Assertions.assertEquals("GSSAPI", AuthMode.KERBEROS.getSaslMechanism());
        Assertions.assertEquals("SIMPLE", AuthMode.SIMPLE.getSaslMechanism());
        Assertions.assertEquals("ANONYMOUS", AuthMode.ANONYMOUS.getSaslMechanism());
    }
}
