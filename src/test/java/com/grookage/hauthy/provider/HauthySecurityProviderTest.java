package com.grookage.hauthy.provider;

import lombok.val;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.security.Security;
import java.util.Arrays;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

class HauthySecurityProviderTest {

    @BeforeEach
    void setUp() {
        HauthySecurityProvider.unregister();
    }

    @AfterEach
    void tearDown() {
        HauthySecurityProvider.unregister();
    }

    @Test
    void testProviderName() {
        assertEquals("Hauthy", HauthySecurityProvider.PROVIDER_NAME);
    }

    @Test
    void testProviderVersion() {
        assertEquals(1.0, HauthySecurityProvider.VERSION);
    }

    @Test
    void testConstructorSetsProviderProperties() {
        assertEquals(HauthySecurityProvider.PROVIDER_NAME, new HauthySecurityProvider().getName());
        assertEquals(HauthySecurityProvider.DESCRIPTION, new HauthySecurityProvider().getInfo());
    }

    @Test
    void testConstructorRegistersSaslFactories() {
        val expectedFactoryClass = "com.grookage.hauthy.factory.DualModeSaslServerFactory";
        assertEquals(expectedFactoryClass, new HauthySecurityProvider().get("SaslServerFactory.DUAL-MODE"));
        assertEquals(expectedFactoryClass, new HauthySecurityProvider().get("SaslServerFactory.GSSAPI"));
        assertEquals(expectedFactoryClass, new HauthySecurityProvider().get("SaslServerFactory.PLAIN"));
        assertEquals(expectedFactoryClass, new HauthySecurityProvider().get("SaslServerFactory.SIMPLE"));
        assertEquals(expectedFactoryClass, new HauthySecurityProvider().get("SaslServerFactory.ANONYMOUS"));
    }

    @Test
    void testRegisterSucceeds() {
        val result = HauthySecurityProvider.register();
        assertTrue(result);
        assertNotNull(Security.getProvider(HauthySecurityProvider.PROVIDER_NAME));
    }

    @Test
    void testRegisterIsIdempotent() {
        val firstResult = HauthySecurityProvider.register();
        val secondResult = HauthySecurityProvider.register();
        assertTrue(firstResult);
        assertFalse(secondResult); // Already registered
        assertNotNull(Security.getProvider(HauthySecurityProvider.PROVIDER_NAME));
    }

    @Test
    void testRegisterAtHighestPriority() {
        HauthySecurityProvider.register();
        val providers = Security.getProviders();
        assertTrue(providers.length > 0);
        // Should be at position 1 (index 0)
        assertEquals(HauthySecurityProvider.PROVIDER_NAME, providers[0].getName());
    }

    @Test
    void testUnregisterWhenNotRegistered() {
        assertDoesNotThrow(HauthySecurityProvider::unregister);
        assertNull(Security.getProvider(HauthySecurityProvider.PROVIDER_NAME));
    }

    @Test
    void testUnregisterWhenRegistered() {
        HauthySecurityProvider.register();
        assertNotNull(Security.getProvider(HauthySecurityProvider.PROVIDER_NAME));
        HauthySecurityProvider.unregister();
        assertNull(Security.getProvider(HauthySecurityProvider.PROVIDER_NAME));
    }

    @Test
    void testUnregisterIsIdempotent() {
        HauthySecurityProvider.register();
        HauthySecurityProvider.unregister();
        assertNull(Security.getProvider(HauthySecurityProvider.PROVIDER_NAME));
        assertDoesNotThrow(HauthySecurityProvider::unregister);
        assertNull(Security.getProvider(HauthySecurityProvider.PROVIDER_NAME));
    }

    @Test
    void testReRegisterAfterUnregister() {
        // First registration
        val firstResult = HauthySecurityProvider.register();
        assertTrue(firstResult);
        assertNotNull(Security.getProvider(HauthySecurityProvider.PROVIDER_NAME));

        // Unregister
        HauthySecurityProvider.unregister();
        assertNull(Security.getProvider(HauthySecurityProvider.PROVIDER_NAME));

        // Re-register
        val secondResult = HauthySecurityProvider.register();
        assertTrue(secondResult);
        assertNotNull(Security.getProvider(HauthySecurityProvider.PROVIDER_NAME));
    }

    @Test
    void testConcurrentRegistrationIsSafe() throws InterruptedException {
        int[] successCount = {0};
        val threads = IntStream.range(0, 10).mapToObj(i -> new Thread(() -> {
            if (HauthySecurityProvider.register()) {
                synchronized (successCount) {
                    successCount[0]++;
                }
            }
        })).toArray(Thread[]::new);
        Arrays.stream(threads).forEach(Thread::start);
        for (Thread thread : threads) {
            thread.join();
        }
        // Only one thread should have successfully registered
        assertEquals(1, successCount[0]);
        assertNotNull(Security.getProvider(HauthySecurityProvider.PROVIDER_NAME));
    }

    @Test
    void testConcurrentUnregistrationIsSafe() throws InterruptedException {
        HauthySecurityProvider.register();
        val threads = IntStream.range(0, 10).mapToObj(i -> new Thread(HauthySecurityProvider::unregister)).toArray(Thread[]::new);
        Arrays.stream(threads).forEach(Thread::start);
        for (Thread thread : threads) {
            thread.join();
        }
        // Should be unregistered
        assertNull(Security.getProvider(HauthySecurityProvider.PROVIDER_NAME));
    }

    @Test
    void testProviderContainsFiveSaslMechanisms() {
        val saslFactoryCount = (int) new HauthySecurityProvider()
                .keySet()
                .stream()
                .filter(key -> key.toString().startsWith("SaslServerFactory."))
                .count();
        assertEquals(5, saslFactoryCount);
    }

    @Test
    void testRegisterHandlesSecurityExceptionOnRemove() {
        // Use reflection to set registered = false so register() will attempt registration
        setRegisteredState(false);

        try (MockedStatic<Security> mockedSecurity = Mockito.mockStatic(Security.class)) {
            mockedSecurity.when(() -> Security.removeProvider(HauthySecurityProvider.PROVIDER_NAME))
                    .thenThrow(new SecurityException("Test security exception"));

            val result = HauthySecurityProvider.register();

            // Should return false when SecurityException is caught
            assertFalse(result);
        } finally {
            // Reset state for other tests
            setRegisteredState(false);
        }
    }

    @Test
    void testRegisterHandlesSecurityExceptionOnInsert() {
        // Use reflection to set registered = false so register() will attempt registration
        setRegisteredState(false);

        try (MockedStatic<Security> mockedSecurity = Mockito.mockStatic(Security.class)) {
            // removeProvider succeeds, but insertProviderAt throws
            mockedSecurity.when(() -> Security.removeProvider(HauthySecurityProvider.PROVIDER_NAME))
                    .then(invocation -> null);
            mockedSecurity.when(() -> Security.insertProviderAt(Mockito.any(), Mockito.eq(1)))
                    .thenThrow(new SecurityException("Test security exception on insert"));

            val result = HauthySecurityProvider.register();

            // Should return false when SecurityException is caught
            assertFalse(result);
        } finally {
            // Reset state for other tests
            setRegisteredState(false);
        }
    }

    @Test
    void testUnregisterHandlesSecurityException() {
        // Use reflection to set registered = true so unregister() will attempt unregistration
        setRegisteredState(true);

        try (MockedStatic<Security> mockedSecurity = Mockito.mockStatic(Security.class)) {
            mockedSecurity.when(() -> Security.removeProvider(HauthySecurityProvider.PROVIDER_NAME))
                    .thenThrow(new SecurityException("Test security exception"));

            // Should not throw, just log the error
            assertDoesNotThrow(HauthySecurityProvider::unregister);
        } finally {
            // Reset state for other tests - also clean up actual Security provider if any
            setRegisteredState(false);
            try {
                Security.removeProvider(HauthySecurityProvider.PROVIDER_NAME);
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Helper method to set the internal 'registered' state using reflection.
     */
    private void setRegisteredState(boolean state) {
        try {
            val field = HauthySecurityProvider.class.getDeclaredField("registered");
            field.setAccessible(true);
            field.setBoolean(null, state);
        } catch (Exception e) {
            fail("Failed to set registered state via reflection: " + e.getMessage());
        }
    }
}
