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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AuthMetrics}.
 */
class AuthMetricsTest {

    private AuthMetrics metrics;

    @BeforeEach
    void setUp() {
        metrics = AuthMetrics.getInstance();
        metrics.reset();
    }

    @Test
    void shouldReturnSingletonInstance() {
        final var instance1 = AuthMetrics.getInstance();
        final var instance2 = AuthMetrics.getInstance();

        Assertions.assertSame(instance1, instance2);
    }

    @Test
    void shouldIncrementKerberosSuccessCounter() {
        final var before = metrics.getKerberosAuthSuccess();

        metrics.recordKerberosSuccess();

        Assertions.assertEquals(before + 1, metrics.getKerberosAuthSuccess());
        Assertions.assertEquals(1, metrics.getTotalConnections());
    }

    @Test
    void shouldIncrementKerberosFailureCounter() {
        final var before = metrics.getKerberosAuthFailure();

        metrics.recordKerberosFailure();

        Assertions.assertEquals(before + 1, metrics.getKerberosAuthFailure());
    }

    @Test
    void shouldIncrementSimpleSuccessCounter() {
        final var before = metrics.getSimpleAuthSuccess();

        metrics.recordSimpleSuccess();

        Assertions.assertEquals(before + 1, metrics.getSimpleAuthSuccess());
        Assertions.assertEquals(1, metrics.getTotalConnections());
    }

    @Test
    void shouldIncrementSimpleRejectedCounter() {
        final var before = metrics.getSimpleAuthRejected();

        metrics.recordSimpleRejected();

        Assertions.assertEquals(before + 1, metrics.getSimpleAuthRejected());
    }

    @Test
    void shouldTrackActiveConnections() {
        Assertions.assertEquals(0, metrics.getActiveConnections());

        metrics.connectionOpened();
        metrics.connectionOpened();

        Assertions.assertEquals(2, metrics.getActiveConnections());

        metrics.connectionClosed();

        Assertions.assertEquals(1, metrics.getActiveConnections());
    }

    @Test
    void shouldReturnZeroPercentageWhenNoConnections() {
        Assertions.assertEquals(0.0, metrics.getKerberosPercentage());
    }

    @Test
    void shouldReturnHundredPercentWhenOnlyKerberos() {
        metrics.recordKerberosSuccess();
        metrics.recordKerberosSuccess();
        metrics.recordKerberosSuccess();

        Assertions.assertEquals(100.0, metrics.getKerberosPercentage());
    }

    @Test
    void shouldReturnZeroPercentWhenOnlySimple() {
        metrics.recordSimpleSuccess();
        metrics.recordSimpleSuccess();

        Assertions.assertEquals(0.0, metrics.getKerberosPercentage());
    }

    @Test
    void shouldCalculateMixedKerberosPercentage() {
        metrics.recordKerberosSuccess();
        metrics.recordKerberosSuccess();
        metrics.recordKerberosSuccess();
        metrics.recordSimpleSuccess();

        Assertions.assertEquals(75.0, metrics.getKerberosPercentage());
    }

    @Test
    void shouldReturnFalseForMigrationCompleteWhenNoConnections() {
        Assertions.assertFalse(metrics.isMigrationComplete());
    }

    @Test
    void shouldReturnTrueForMigrationCompleteWhenAllKerberos() {
        metrics.recordKerberosSuccess();
        metrics.recordKerberosSuccess();

        Assertions.assertTrue(metrics.isMigrationComplete());
    }

    @Test
    void shouldReturnFalseForMigrationCompleteWhenHasSimple() {
        metrics.recordKerberosSuccess();
        metrics.recordSimpleSuccess();

        Assertions.assertFalse(metrics.isMigrationComplete());
    }

    @Test
    void shouldCreateAccurateSnapshot() {
        metrics.recordKerberosSuccess();
        metrics.recordSimpleSuccess();
        metrics.recordKerberosFailure();

        final var snapshot = metrics.snapshot();

        Assertions.assertEquals(1, snapshot.getKerberosSuccess());
        Assertions.assertEquals(1, snapshot.getSimpleSuccess());
        Assertions.assertEquals(1, snapshot.getKerberosFailure());
        Assertions.assertEquals(2, snapshot.getTotalConnections());
        Assertions.assertEquals(50.0, snapshot.getKerberosPercentage());
        Assertions.assertTrue(snapshot.getTimestamp() > 0);
    }

    @Test
    void shouldGenerateSummaryString() {
        metrics.recordKerberosSuccess();
        metrics.recordSimpleSuccess();

        final var summary = metrics.getSummary();

        Assertions.assertTrue(summary.contains("kerberos=1"));
        Assertions.assertTrue(summary.contains("simple=1"));
    }

    @Test
    void shouldResetAllCounters() {
        metrics.recordKerberosSuccess();
        metrics.recordSimpleSuccess();
        metrics.recordKerberosFailure();
        metrics.recordSimpleRejected();

        metrics.reset();

        Assertions.assertEquals(0, metrics.getKerberosAuthSuccess());
        Assertions.assertEquals(0, metrics.getSimpleAuthSuccess());
        Assertions.assertEquals(0, metrics.getKerberosAuthFailure());
        Assertions.assertEquals(0, metrics.getSimpleAuthRejected());
        Assertions.assertEquals(0, metrics.getTotalConnections());
    }
}
