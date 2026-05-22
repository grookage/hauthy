package com.grookage.hauthy.metrics;

/**
 * JMX MXBean interface for authentication metrics.
 *
 * <p>This interface defines the metrics exposed via JMX for monitoring
 * the dual-mode authentication migration progress.</p>
 */
@SuppressWarnings("unused")
public interface AuthMetricsMXBean {

    /**
     * Get the count of successful Kerberos authentications.
     *
     * @return count of successful Kerberos auths
     */
    long getKerberosAuthSuccess();

    /**
     * Get the count of failed Kerberos authentication attempts.
     *
     * @return count of failed Kerberos auths
     */
    long getKerberosAuthFailure();

    /**
     * Get the count of successful simple authentications.
     *
     * @return count of successful simple auths
     */
    long getSimpleAuthSuccess();

    /**
     * Get the count of rejected simple authentication attempts.
     *
     * @return count of rejected simple auths
     */
    long getSimpleAuthRejected();

    /**
     * Get the total number of connections processed.
     *
     * @return total connection count
     */
    long getTotalConnections();

    /**
     * Get the current number of active connections.
     *
     * @return active connection count
     */
    long getActiveConnections();

    /**
     * Get the percentage of connections using Kerberos authentication.
     *
     * <p>This is the key metric for tracking migration progress.
     * Target is 100% before disabling simple auth.</p>
     *
     * @return percentage of Kerberos connections (0-100)
     */
    double getKerberosPercentage();

    /**
     * Get the count of ZK SASL no-op fallbacks (KDC server-not-found → skip auth).
     *
     * <p>Fires when DualModeSaslClient detects the target ZK server principal
     * is missing from the KDC and falls back to an unauthenticated session.
     * Non-zero means cross-cluster replication is using the no-op path.</p>
     *
     * @return count of ZK SASL no-op fallbacks
     */
    long getZkSaslNoOpFallback();
}
