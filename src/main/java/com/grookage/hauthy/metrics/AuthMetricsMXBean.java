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
package com.grookage.hauthy.metrics;

/**
 * JMX MXBean interface for authentication metrics.
 *
 * <p>This interface defines the metrics exposed via JMX for monitoring
 * the dual-mode authentication migration progress.</p>
 */
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
}
