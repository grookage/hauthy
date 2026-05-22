package com.grookage.hauthy.metrics;

import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.management.ObjectName;
import java.lang.management.ManagementFactory;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

class AuthMetricsTest {

    private AuthMetrics metrics;

    @BeforeEach
    void setUp() {
        metrics = AuthMetrics.getInstance();
        metrics.reset();
    }

    @Test
    void testSingletonInstance() {
        val instance1 = AuthMetrics.getInstance();
        val instance2 = AuthMetrics.getInstance();
        assertSame(instance1, instance2);
    }

    @Test
    void testRecordKerberosSuccess() {
        assertEquals(0, metrics.getKerberosAuthSuccess());
        assertEquals(0, metrics.getTotalConnections());
        val initialActive = metrics.getActiveConnections();

        metrics.recordKerberosSuccess();

        assertEquals(1, metrics.getKerberosAuthSuccess());
        assertEquals(1, metrics.getTotalConnections());
        assertEquals(initialActive + 1, metrics.getActiveConnections());

        // Clean up
        metrics.connectionClosed();
    }

    @Test
    void testRecordKerberosFailure() {
        assertEquals(0, metrics.getKerberosAuthFailure());

        metrics.recordKerberosFailure();

        assertEquals(1, metrics.getKerberosAuthFailure());
        // Failures should not increment total connections
        assertEquals(0, metrics.getTotalConnections());
    }

    @Test
    void testRecordSimpleSuccess() {
        assertEquals(0, metrics.getSimpleAuthSuccess());
        assertEquals(0, metrics.getTotalConnections());
        val initialActive = metrics.getActiveConnections();

        metrics.recordSimpleSuccess();

        assertEquals(1, metrics.getSimpleAuthSuccess());
        assertEquals(1, metrics.getTotalConnections());
        assertEquals(initialActive + 1, metrics.getActiveConnections());

        // Clean up
        metrics.connectionClosed();
    }

    @Test
    void testRecordSimpleRejected() {
        assertEquals(0, metrics.getSimpleAuthRejected());

        metrics.recordSimpleRejected();

        assertEquals(1, metrics.getSimpleAuthRejected());
        // Rejections should not increment total connections
        assertEquals(0, metrics.getTotalConnections());
    }

    @Test
    void testConnectionOpenedAndClosed() {
        val initialActive = metrics.getActiveConnections();

        metrics.connectionOpened();
        assertEquals(initialActive + 1, metrics.getActiveConnections());

        metrics.connectionOpened();
        assertEquals(initialActive + 2, metrics.getActiveConnections());

        metrics.connectionClosed();
        assertEquals(initialActive + 1, metrics.getActiveConnections());

        metrics.connectionClosed();
        assertEquals(initialActive, metrics.getActiveConnections());
    }

    @Test
    void testKerberosPercentageWithNoConnections() {
        assertEquals(0.0, metrics.getKerberosPercentage());
    }

    @Test
    void testKerberosPercentageWithOnlyKerberos() {
        metrics.recordKerberosSuccess();
        metrics.recordKerberosSuccess();
        metrics.recordKerberosSuccess();

        assertEquals(100.0, metrics.getKerberosPercentage());
    }

    @Test
    void testKerberosPercentageWithOnlySimple() {
        metrics.recordSimpleSuccess();
        metrics.recordSimpleSuccess();

        assertEquals(0.0, metrics.getKerberosPercentage());
    }

    @Test
    void testKerberosPercentageMixed() {
        // 3 Kerberos, 1 Simple = 75%
        metrics.recordKerberosSuccess();
        metrics.recordKerberosSuccess();
        metrics.recordKerberosSuccess();
        metrics.recordSimpleSuccess();

        assertEquals(75.0, metrics.getKerberosPercentage());
    }

    @Test
    void testKerberosPercentage5050() {
        metrics.recordKerberosSuccess();
        metrics.recordSimpleSuccess();

        assertEquals(50.0, metrics.getKerberosPercentage());
    }

    @Test
    void testIsMigrationCompleteWhenNoConnections() {
        assertFalse(metrics.isMigrationComplete());
    }

    @Test
    void testIsMigrationCompleteWithOnlyKerberos() {
        metrics.recordKerberosSuccess();
        assertTrue(metrics.isMigrationComplete());
    }

    @Test
    void testIsMigrationCompleteWithMixedAuth() {
        metrics.recordKerberosSuccess();
        metrics.recordSimpleSuccess();
        assertFalse(metrics.isMigrationComplete());
    }

    @Test
    void testIsMigrationCompleteWithOnlySimple() {
        metrics.recordSimpleSuccess();
        assertFalse(metrics.isMigrationComplete());
    }

    @Test
    void testReset() {
        val initialActive = metrics.getActiveConnections();

        metrics.recordKerberosSuccess();
        metrics.recordKerberosFailure();
        metrics.recordSimpleSuccess();
        metrics.recordSimpleRejected();

        metrics.reset();

        assertEquals(0, metrics.getKerberosAuthSuccess());
        assertEquals(0, metrics.getKerberosAuthFailure());
        assertEquals(0, metrics.getSimpleAuthSuccess());
        assertEquals(0, metrics.getSimpleAuthRejected());
        assertEquals(0, metrics.getTotalConnections());
        // Active connections should not be reset - should be initial + 2 (from kerberos + simple success)
        assertEquals(initialActive + 2, metrics.getActiveConnections());

        // Clean up
        metrics.connectionClosed();
        metrics.connectionClosed();
    }

    @Test
    void testSnapshot() {
        val initialActive = metrics.getActiveConnections();

        metrics.recordKerberosSuccess();
        metrics.recordKerberosSuccess();
        metrics.recordKerberosFailure();
        metrics.recordSimpleSuccess();
        metrics.recordSimpleRejected();

        AuthMetrics.MetricsSnapshot snapshot = metrics.snapshot();

        assertEquals(2, snapshot.getKerberosSuccess());
        assertEquals(1, snapshot.getKerberosFailure());
        assertEquals(1, snapshot.getSimpleSuccess());
        assertEquals(1, snapshot.getSimpleRejected());
        assertEquals(3, snapshot.getTotalConnections());
        // activeConnections incremented by 2 kerberos + 1 simple success = 3
        assertEquals(initialActive + 3, snapshot.getActiveConnections());
        // 2 kerberos / (2 kerberos + 1 simple) = 66.67%
        assertEquals(200.0 / 3.0, snapshot.getKerberosPercentage(), 0.01);
        assertTrue(snapshot.getTimestamp() > 0);

        // Clean up
        metrics.connectionClosed();
        metrics.connectionClosed();
        metrics.connectionClosed();
    }

    @Test
    void testSnapshotIsImmutable() {
        metrics.recordKerberosSuccess();
        AuthMetrics.MetricsSnapshot snapshot = metrics.snapshot();

        val originalValue = snapshot.getKerberosSuccess();

        // Record more after snapshot
        metrics.recordKerberosSuccess();
        metrics.recordKerberosSuccess();

        // Snapshot should still have original value
        assertEquals(originalValue, snapshot.getKerberosSuccess());
        // But metrics should have new value
        assertEquals(3, metrics.getKerberosAuthSuccess());
    }

    @Test
    void testGetSummary() {
        metrics.recordKerberosSuccess();
        metrics.recordSimpleSuccess();

        val summary = metrics.getSummary();

        assertNotNull(summary);
        assertTrue(summary.contains("kerberos=1"));
        assertTrue(summary.contains("simple=1"));
        assertTrue(summary.contains("50.00"));
    }

    @Test
    void testJmxRegistration() {
        assertTrue(metrics.isJmxRegistered());
    }

    @Test
    void testJmxMBeanAccessible() throws Exception {
        val mbs = ManagementFactory.getPlatformMBeanServer();
        val name = new ObjectName("com.grookage.hauthy:type=AuthMetrics");

        assertTrue(mbs.isRegistered(name));

        // Test accessing attributes via JMX
        metrics.recordKerberosSuccess();
        val kerberosSuccess = (Long) mbs.getAttribute(name, "KerberosAuthSuccess");
        assertTrue(kerberosSuccess >= 1);
    }

    @Test
    void testMultipleRecordsAccumulate() {
        IntStream.range(0, 100).forEach(i -> metrics.recordKerberosSuccess());
        IntStream.range(0, 50).forEach(i -> metrics.recordSimpleSuccess());

        assertEquals(100, metrics.getKerberosAuthSuccess());
        assertEquals(50, metrics.getSimpleAuthSuccess());
        assertEquals(150, metrics.getTotalConnections());
        // 100 / 150 = 66.67%
        assertEquals(200.0 / 3.0, metrics.getKerberosPercentage(), 0.01);
    }

    @Test
    void testActiveConnectionsTrackedOnAuthSuccess() {
        val initialActive = metrics.getActiveConnections();

        metrics.recordKerberosSuccess();
        assertEquals(initialActive + 1, metrics.getActiveConnections());

        metrics.recordSimpleSuccess();
        assertEquals(initialActive + 2, metrics.getActiveConnections());

        metrics.connectionClosed();
        metrics.connectionClosed();
        assertEquals(initialActive, metrics.getActiveConnections());
    }

    @Test
    void testLogSummaryDoesNotThrow() {
        // Ensure logSummary doesn't throw with zero metrics
        assertDoesNotThrow(() -> metrics.logSummary());
    }

    @Test
    void testLogSummaryWithKerberosMetrics() {
        metrics.recordKerberosSuccess();
        metrics.recordKerberosSuccess();
        metrics.recordKerberosFailure();

        // Should not throw
        assertDoesNotThrow(() -> metrics.logSummary());
    }

    @Test
    void testLogSummaryWithSimpleMetrics() {
        metrics.recordSimpleSuccess();
        metrics.recordSimpleRejected();

        // Should not throw
        assertDoesNotThrow(() -> metrics.logSummary());
    }

    @Test
    void testLogSummaryWithMixedMetrics() {
        metrics.recordKerberosSuccess();
        metrics.recordKerberosFailure();
        metrics.recordSimpleSuccess();
        metrics.recordSimpleRejected();

        // Should not throw
        assertDoesNotThrow(() -> metrics.logSummary());

        // Clean up
        metrics.connectionClosed();
        metrics.connectionClosed();
    }

    @Test
    void testLogSummaryWithActiveConnections() {
        metrics.recordKerberosSuccess();

        // Should not throw and should include active connections
        assertDoesNotThrow(() -> metrics.logSummary());

        // Clean up
        metrics.connectionClosed();
    }
}
