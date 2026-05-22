package com.grookage.hauthy.core;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class AuthModeTest {

    @Test
    public void testFromMechanisms() {
        Assertions.assertEquals(AuthMode.KERBEROS, AuthMode.fromMechanism("GSSAPI"));
        Assertions.assertEquals(AuthMode.KERBEROS, AuthMode.fromMechanism("gssAPI"));
        Assertions.assertEquals(AuthMode.SIMPLE, AuthMode.fromMechanism("SIMPLE"));
        Assertions.assertEquals(AuthMode.SIMPLE, AuthMode.fromMechanism("PLAIN"));
        Assertions.assertEquals(AuthMode.SIMPLE, AuthMode.fromMechanism("plain"));
        Assertions.assertEquals(AuthMode.SIMPLE, AuthMode.fromMechanism("siMple"));
        Assertions.assertEquals(AuthMode.SIMPLE, AuthMode.fromMechanism(null));
        Assertions.assertEquals(AuthMode.SIMPLE, AuthMode.fromMechanism("UNKNOWN"));
        Assertions.assertEquals(AuthMode.ANONYMOUS, AuthMode.fromMechanism("anonyMous"));
        Assertions.assertFalse(AuthMode.ANONYMOUS.requiresKerberos());
        Assertions.assertTrue(AuthMode.KERBEROS.requiresKerberos());
    }
}
