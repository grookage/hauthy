package com.grookage.hauthy.metrics;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

import javax.management.ObjectName;
import java.lang.management.ManagementFactory;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Metrics for dual-mode authentication.
 *
 * <p>Provides counters for tracking authentication attempts, successes, and failures.
 * Metrics are exposed via JMX for monitoring migration progress.</p>
 *
 * <h3>JMX MBean:</h3>
 * <pre>
 * com.grookage.hauthy:type=AuthMetrics
 *   - KerberosAuthSuccess: long
 *   - KerberosAuthFailure: long
 *   - SimpleAuthSuccess: long
 *   - SimpleAuthRejected: long
 *   - TotalConnections: long
 *   - ActiveConnections: long
 *   - KerberosPercentage: double
 * </pre>
 *
 * <h3>Usage:</h3>
 * <pre>{@code
 * AuthMetrics metrics = AuthMetrics.getInstance();
 * metrics.recordKerberosSuccess();
 *
 * // Check migration progress
 * double progress = metrics.getKerberosPercentage();
 * System.out.println("Migration progress: " + progress + "% using Kerberos");
 * }</pre>
 */
@SuppressWarnings("unused")
@Slf4j
public class AuthMetrics implements AuthMetricsMXBean {

    private static final String JMX_OBJECT_NAME = "com.grookage.hauthy:type=AuthMetrics";
    //Eager init is fine, don't need lazy loading here and it simplifies JMX registration
    private static final AuthMetrics INSTANCE = new AuthMetrics();

    // Counters
    private final AtomicLong kerberosAuthSuccess = new AtomicLong(0);
    private final AtomicLong kerberosAuthFailure = new AtomicLong(0);
    private final AtomicLong simpleAuthSuccess = new AtomicLong(0);
    private final AtomicLong simpleAuthRejected = new AtomicLong(0);
    private final AtomicLong totalConnections = new AtomicLong(0);
    private final AtomicLong activeConnections = new AtomicLong(0);
    private final AtomicLong zkSaslNoOpFallback = new AtomicLong(0);

    // JMX registration status
    @Getter
    private boolean jmxRegistered = false;

    private AuthMetrics() {
        registerJmx();
    }

    /**
     * Get the singleton instance of AuthMetrics.
     *
     * @return AuthMetrics instance
     */
    public static AuthMetrics getInstance() {
        return INSTANCE;
    }

    /**
     * Register this metrics instance with JMX.
     */
    private void registerJmx() {
        try {
            val mbs = ManagementFactory.getPlatformMBeanServer();
            val name = new ObjectName(JMX_OBJECT_NAME);

            // Unregister if already registered
            if (mbs.isRegistered(name)) {
                mbs.unregisterMBean(name);
            }

            mbs.registerMBean(this, name);
            jmxRegistered = true;
            log.info("Registered AuthMetrics MBean: {}", JMX_OBJECT_NAME);
        } catch (Exception e) {
            log.warn("Failed to register AuthMetrics MBean: {}", e.getMessage());
        }
    }


    /**
     * Record a successful Kerberos authentication.
     */
    public void recordKerberosSuccess() {
        kerberosAuthSuccess.incrementAndGet();
        totalConnections.incrementAndGet();
        activeConnections.incrementAndGet();
    }

    /**
     * Record a failed Kerberos authentication attempt.
     */
    public void recordKerberosFailure() {
        kerberosAuthFailure.incrementAndGet();
    }

    /**
     * Record a successful simple authentication.
     */
    public void recordSimpleSuccess() {
        simpleAuthSuccess.incrementAndGet();
        totalConnections.incrementAndGet();
        activeConnections.incrementAndGet();
    }

    /**
     * Record a rejected simple authentication attempt.
     */
    public void recordSimpleRejected() {
        simpleAuthRejected.incrementAndGet();
    }

    /**
     * Record a new connection opened.
     */
    public void connectionOpened() {
        activeConnections.incrementAndGet();
    }

    /**
     * Record a connection closed.
     */
    public void connectionClosed() {
        activeConnections.decrementAndGet();
    }

    /**
     * Record a ZK SASL no-op fallback (DualModeSaslClient detected server-not-found in KDC).
     */
    public void recordZkSaslNoOpFallback() {
        zkSaslNoOpFallback.incrementAndGet();
    }

    @Override
    public long getKerberosAuthSuccess() {
        return kerberosAuthSuccess.get();
    }

    @Override
    public long getKerberosAuthFailure() {
        return kerberosAuthFailure.get();
    }

    @Override
    public long getSimpleAuthSuccess() {
        return simpleAuthSuccess.get();
    }

    @Override
    public long getSimpleAuthRejected() {
        return simpleAuthRejected.get();
    }

    @Override
    public long getTotalConnections() {
        return totalConnections.get();
    }

    @Override
    public long getActiveConnections() {
        return activeConnections.get();
    }

    @Override
    public double getKerberosPercentage() {
        val kerberos = kerberosAuthSuccess.get();
        val simple = simpleAuthSuccess.get();
        val total = kerberos + simple;

        if (total == 0) {
            return 0.0;
        }

        return (kerberos * 100.0) / total;
    }

    @Override
    public long getZkSaslNoOpFallback() {
        return zkSaslNoOpFallback.get();
    }

    /**
     * Get a formatted summary of current metrics.
     *
     * @return metrics summary string
     */
    public String getSummary() {
        return String.format(
                "AuthMetrics[kerberos=%d/%d, simple=%d/%d, total=%d, active=%d, kerberos%%=%.2f]",
                kerberosAuthSuccess.get(),
                kerberosAuthFailure.get(),
                simpleAuthSuccess.get(),
                simpleAuthRejected.get(),
                totalConnections.get(),
                activeConnections.get(),
                getKerberosPercentage()
        );
    }

    /**
     * Log the current metrics summary.
     */
    public void logSummary() {
        log.info("Auth Metrics: Kerberos {} success / {} fail, Simple {} success / {} rejected, " +
                        "Kerberos %: {}%, Active: {}",
                kerberosAuthSuccess.get(),
                kerberosAuthFailure.get(),
                simpleAuthSuccess.get(),
                simpleAuthRejected.get(),
                String.format("%.2f", getKerberosPercentage()),
                activeConnections.get());
    }

    /**
     * Check if migration is complete (100% Kerberos, 0 simple connections).
     *
     * @return true if all connections are using Kerberos
     */
    public boolean isMigrationComplete() {
        return simpleAuthSuccess.get() == 0 && kerberosAuthSuccess.get() > 0;
    }

    /**
     * Reset all counters. Use with caution - mainly for testing.
     */
    public void reset() {
        kerberosAuthSuccess.set(0);
        kerberosAuthFailure.set(0);
        simpleAuthSuccess.set(0);
        simpleAuthRejected.set(0);
        totalConnections.set(0);
        // Don't reset activeConnections as it tracks current state
    }

    /**
     * Create a snapshot of current metrics.
     *
     * @return MetricsSnapshot containing current values
     */
    public MetricsSnapshot snapshot() {
        return new MetricsSnapshot(
                kerberosAuthSuccess.get(),
                kerberosAuthFailure.get(),
                simpleAuthSuccess.get(),
                simpleAuthRejected.get(),
                totalConnections.get(),
                activeConnections.get()
        );
    }

    /**
     * Immutable snapshot of metrics at a point in time.
     */
    @Getter
    public static class MetricsSnapshot {
        private final long kerberosSuccess;
        private final long kerberosFailure;
        private final long simpleSuccess;
        private final long simpleRejected;
        private final long totalConnections;
        private final long activeConnections;
        private final double kerberosPercentage;
        private final long timestamp;

        public MetricsSnapshot(long kerberosSuccess, long kerberosFailure,
                               long simpleSuccess, long simpleRejected,
                               long totalConnections, long activeConnections) {
            this.kerberosSuccess = kerberosSuccess;
            this.kerberosFailure = kerberosFailure;
            this.simpleSuccess = simpleSuccess;
            this.simpleRejected = simpleRejected;
            this.totalConnections = totalConnections;
            this.activeConnections = activeConnections;
            this.timestamp = System.currentTimeMillis();

            long total = kerberosSuccess + simpleSuccess;
            this.kerberosPercentage = total > 0 ? (kerberosSuccess * 100.0) / total : 0.0;
        }
    }
}
