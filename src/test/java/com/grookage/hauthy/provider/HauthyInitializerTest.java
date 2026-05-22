package com.grookage.hauthy.provider;

import com.grookage.hauthy.core.HauthyConfig;
import com.grookage.hauthy.metrics.AuthMetrics;
import lombok.val;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.IOException;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.Arrays;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

class HauthyInitializerTest {

    private Configuration conf;

    @BeforeEach
    void setUp() {
        // Ensure clean state before each test
        HauthyInitializer.shutdown();
        conf = new Configuration();
    }

    @AfterEach
    void tearDown() {
        // Clean up after each test
        HauthyInitializer.shutdown();
    }

    @Test
    void testInitialStateIsNotInitialized() {
        assertFalse(HauthyInitializer.isInitialized());
    }

    @Test
    void testGetMetricsReturnsNullWhenNotInitialized() {
        assertNull(HauthyInitializer.getMetrics());
    }

    @Test
    void testInitializeWithDisabledConfig() throws IOException {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, false);
        HauthyInitializer.initialize(conf);
        assertFalse(HauthyInitializer.isInitialized());
    }

    @Test
    void testInitializeWithEnabledConfig() throws IOException {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);
        conf.setBoolean(HauthyConfig.ALLOW_SIMPLE, true);
        conf.setBoolean(HauthyConfig.ALLOW_KERBEROS, true);

        HauthyInitializer.initialize(conf);

        assertTrue(HauthyInitializer.isInitialized());
    }

    @Test
    void testGetMetricsReturnsInstanceWhenInitialized() throws IOException {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);

        HauthyInitializer.initialize(conf);

        AuthMetrics metrics = HauthyInitializer.getMetrics();
        assertNotNull(metrics);
        assertSame(AuthMetrics.getInstance(), metrics);
    }

    @Test
    void testInitializeIsIdempotent() throws IOException {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);

        HauthyInitializer.initialize(conf);
        assertTrue(HauthyInitializer.isInitialized());

        // Second call should not throw and should remain initialized
        HauthyInitializer.initialize(conf);
        assertTrue(HauthyInitializer.isInitialized());
    }

    @Test
    void testShutdownWhenNotInitialized() {
        assertFalse(HauthyInitializer.isInitialized());

        // Should not throw
        HauthyInitializer.shutdown();

        assertFalse(HauthyInitializer.isInitialized());
    }

    @Test
    void testShutdownWhenInitialized() throws IOException {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);

        HauthyInitializer.initialize(conf);
        assertTrue(HauthyInitializer.isInitialized());

        HauthyInitializer.shutdown();

        assertFalse(HauthyInitializer.isInitialized());
    }

    @Test
    void testShutdownIsIdempotent() throws IOException {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);

        HauthyInitializer.initialize(conf);

        HauthyInitializer.shutdown();
        assertFalse(HauthyInitializer.isInitialized());

        // Second shutdown should not throw
        HauthyInitializer.shutdown();
        assertFalse(HauthyInitializer.isInitialized());
    }

    @Test
    void testReInitializeAfterShutdown() throws IOException {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);

        // First initialization
        HauthyInitializer.initialize(conf);
        assertTrue(HauthyInitializer.isInitialized());

        // Shutdown
        HauthyInitializer.shutdown();
        assertFalse(HauthyInitializer.isInitialized());

        // Re-initialize
        HauthyInitializer.initialize(conf);
        assertTrue(HauthyInitializer.isInitialized());
    }

    @Test
    void testInitializeWithSimpleOnlyConfig() throws IOException {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);
        conf.setBoolean(HauthyConfig.ALLOW_SIMPLE, true);
        conf.setBoolean(HauthyConfig.ALLOW_KERBEROS, false);

        HauthyInitializer.initialize(conf);

        assertTrue(HauthyInitializer.isInitialized());
    }

    @Test
    void testInitializeWithKerberosOnlyConfig() {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);
        conf.setBoolean(HauthyConfig.ALLOW_SIMPLE, false);
        conf.setBoolean(HauthyConfig.ALLOW_KERBEROS, true);

        // This may fail in test environment without Kerberos setup
        // But should not throw if simple is also allowed
        try {
            HauthyInitializer.initialize(conf);
            // If it succeeds, verify state
            assertTrue(HauthyInitializer.isInitialized());
        } catch (IOException e) {
            // Expected in test environment without Kerberos
            assertFalse(HauthyInitializer.isInitialized());
        }
    }

    @Test
    void testInitializeWithMetricsDisabled() throws IOException {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);
        conf.setBoolean(HauthyConfig.METRICS_ENABLED, false);

        HauthyInitializer.initialize(conf);

        assertTrue(HauthyInitializer.isInitialized());
    }

    @Test
    void testInitializeWithCustomSimpleDefaultUser() throws IOException {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);
        conf.set(HauthyConfig.SIMPLE_DEFAULT_USER, "custom_user");

        HauthyInitializer.initialize(conf);

        assertTrue(HauthyInitializer.isInitialized());
    }

    @Test
    void testInitializeWithAllowedHosts() throws IOException {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);
        conf.set(HauthyConfig.SIMPLE_ALLOWED_HOSTS, "10.0.0.*,192.168.1.*");

        HauthyInitializer.initialize(conf);

        assertTrue(HauthyInitializer.isInitialized());
    }

    @Test
    void testInitializeRegistersSecurityProvider() throws IOException {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);
        HauthyInitializer.initialize(conf);
        assertNotNull(Security.getProvider(HauthySecurityProvider.PROVIDER_NAME));
    }

    @Test
    void testShutdownUnregistersSecurityProvider() throws IOException {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);
        HauthyInitializer.initialize(conf);
        assertNotNull(Security.getProvider(HauthySecurityProvider.PROVIDER_NAME));
        HauthyInitializer.shutdown();
        assertNull(Security.getProvider(HauthySecurityProvider.PROVIDER_NAME));
    }

    @Test
    void testConcurrentInitializationIsSafe() throws InterruptedException {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);

        val threads = IntStream.range(0, 10).mapToObj(i -> new Thread(() -> {
            try {
                HauthyInitializer.initialize(conf);
            } catch (IOException e) {
                fail("Initialization should not throw: " + e.getMessage());
            }
        })).toArray(Thread[]::new);

        // Start all threads
        Arrays.stream(threads).forEach(Thread::start);

        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }

        // Should be initialized exactly once
        assertTrue(HauthyInitializer.isInitialized());
    }

    @Test
    void testConcurrentShutdownIsSafe() throws InterruptedException, IOException {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);
        HauthyInitializer.initialize(conf);

        val threads = IntStream.range(0, 10).mapToObj(i -> new Thread(HauthyInitializer::shutdown)).toArray(Thread[]::new);

        // Start all threads
        Arrays.stream(threads).forEach(Thread::start);

        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }

        // Should be shut down
        assertFalse(HauthyInitializer.isInitialized());
    }

    @Test
    void testInitializeFactoryWithSecurityDisabled() throws IOException {
        // When Hadoop security is not enabled, initializeFactory should log warning
        // and continue with null subject/principal
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);
        conf.setBoolean(HauthyConfig.ALLOW_SIMPLE, true);
        conf.setBoolean(HauthyConfig.ALLOW_KERBEROS, true);

        try (MockedStatic<UserGroupInformation> mockedUGI = Mockito.mockStatic(UserGroupInformation.class)) {
            mockedUGI.when(UserGroupInformation::isSecurityEnabled).thenReturn(false);

            HauthyInitializer.initialize(conf);

            assertTrue(HauthyInitializer.isInitialized());
            mockedUGI.verify(UserGroupInformation::isSecurityEnabled);
        }
    }

    @Test
    void testInitializeFactoryWithSecurityEnabledAndKerberosLogin() throws IOException {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);
        conf.setBoolean(HauthyConfig.ALLOW_SIMPLE, true);
        conf.setBoolean(HauthyConfig.ALLOW_KERBEROS, true);

        val mockUGI = Mockito.mock(UserGroupInformation.class);
        Mockito.when(mockUGI.getUserName()).thenReturn("hbase/testhost@REALM");
        Mockito.when(mockUGI.doAs(Mockito.<PrivilegedAction<Object>>any())).thenReturn(null);

        try (MockedStatic<UserGroupInformation> mockedUGI = Mockito.mockStatic(UserGroupInformation.class)) {
            mockedUGI.when(UserGroupInformation::isSecurityEnabled).thenReturn(true);
            mockedUGI.when(UserGroupInformation::getLoginUser).thenReturn(mockUGI);

            HauthyInitializer.initialize(conf);

            assertTrue(HauthyInitializer.isInitialized());
            mockedUGI.verify(UserGroupInformation::getLoginUser);
        }
    }

    @Test
    void testInitializeFactoryKerberosLoginFailsWithSimpleAllowed() throws IOException {
        // When Kerberos login fails but simple auth is allowed, should continue
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);
        conf.setBoolean(HauthyConfig.ALLOW_SIMPLE, true);
        conf.setBoolean(HauthyConfig.ALLOW_KERBEROS, true);

        try (MockedStatic<UserGroupInformation> mockedUGI = Mockito.mockStatic(UserGroupInformation.class)) {
            mockedUGI.when(UserGroupInformation::isSecurityEnabled).thenReturn(true);
            mockedUGI.when(UserGroupInformation::getLoginUser).thenThrow(new IOException("Kerberos login failed"));

            // Should not throw because simple auth is allowed
            HauthyInitializer.initialize(conf);

            assertTrue(HauthyInitializer.isInitialized());
        }
    }

    @Test
    void testInitializeFactoryKerberosLoginFailsWithKerberosOnlyThrows() {
        // When Kerberos login fails and only Kerberos is allowed, should throw
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);
        conf.setBoolean(HauthyConfig.ALLOW_SIMPLE, false);
        conf.setBoolean(HauthyConfig.ALLOW_KERBEROS, true);

        try (MockedStatic<UserGroupInformation> mockedUGI = Mockito.mockStatic(UserGroupInformation.class)) {
            mockedUGI.when(UserGroupInformation::isSecurityEnabled).thenReturn(true);
            mockedUGI.when(UserGroupInformation::getLoginUser).thenThrow(new IOException("Kerberos login failed"));

            // Should throw because Kerberos is required
            assertThrows(IOException.class, () -> HauthyInitializer.initialize(conf));
            assertFalse(HauthyInitializer.isInitialized());
        }
    }

    @Test
    void testInitializeFactoryWithSecurityEnabledExtractsPrincipal() throws IOException {
        conf.setBoolean(HauthyConfig.HAUTHY_ENABLED, true);
        conf.setBoolean(HauthyConfig.ALLOW_SIMPLE, true);
        conf.setBoolean(HauthyConfig.ALLOW_KERBEROS, true);

        val expectedPrincipal = "hbase/myhost.example.com@EXAMPLE.COM";
        val mockUGI = Mockito.mock(UserGroupInformation.class);
        Mockito.when(mockUGI.getUserName()).thenReturn(expectedPrincipal);
        Mockito.when(mockUGI.doAs(Mockito.<PrivilegedAction<Object>>any())).thenReturn(null);

        try (MockedStatic<UserGroupInformation> mockedUGI = Mockito.mockStatic(UserGroupInformation.class)) {
            mockedUGI.when(UserGroupInformation::isSecurityEnabled).thenReturn(true);
            mockedUGI.when(UserGroupInformation::getLoginUser).thenReturn(mockUGI);

            HauthyInitializer.initialize(conf);

            assertTrue(HauthyInitializer.isInitialized());
            Mockito.verify(mockUGI).getUserName();
            Mockito.verify(mockUGI).doAs(Mockito.<PrivilegedAction<Object>>any());
        }
    }
}
