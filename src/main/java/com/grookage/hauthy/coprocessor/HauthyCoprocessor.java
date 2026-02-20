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
package com.grookage.hauthy.coprocessor;

import com.grookage.hauthy.provider.HauthyInitializer;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.CoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.*;

import java.util.Optional;

/**
 * HBase Coprocessor that initializes Hauthy dual-mode authentication.
 *
 * <p>This coprocessor should be loaded on both Master and RegionServer to enable
 * dual-mode authentication across the cluster.</p>
 *
 * <h3>Configuration:</h3>
 * <pre>{@code
 * <!-- In hbase-site.xml -->
 * <property>
 *     <name>hbase.coprocessor.master.classes</name>
 *     <value>com.grookage.hauthy.coprocessor.HauthyCoprocessor</value>
 * </property>
 * <property>
 *     <name>hbase.coprocessor.regionserver.classes</name>
 *     <value>com.grookage.hauthy.coprocessor.HauthyCoprocessor</value>
 * </property>
 * }</pre>
 *
 * <h3>Alternative:</h3>
 * <p>If you prefer not to use a coprocessor, you can call
 * {@link HauthyInitializer#initialize(Configuration)} directly during HBase startup.</p>
 */
@Slf4j
@SuppressWarnings("rawtypes")
public class HauthyCoprocessor implements MasterCoprocessor, RegionServerCoprocessor,
        MasterObserver, RegionServerObserver {

    @Override
    public void start(CoprocessorEnvironment env) {
        log.info("HauthyCoprocessor starting on {}", getEnvironmentType(env));
        final var conf = env.getConfiguration();

        try {
            HauthyInitializer.initialize(conf);
            log.info("HauthyCoprocessor started successfully");
        } catch (Exception e) {
            // Don't throw - allow HBase to start even if Hauthy fails
            // This prevents a misconfiguration from taking down the cluster
            log.error("Failed to initialize Hauthy in coprocessor", e);
        }
    }

    @Override
    public void stop(CoprocessorEnvironment env) {
        // Don't shutdown Hauthy here - other coprocessors might still need it
        // Hauthy will be cleaned up when JVM exits
        log.info("HauthyCoprocessor stopping on {}", getEnvironmentType(env));
    }

    @Override
    public Optional<MasterObserver> getMasterObserver() {
        return Optional.of(this);
    }

    @Override
    public Optional<RegionServerObserver> getRegionServerObserver() {
        return Optional.of(this);
    }

    /**
     * Get a description of the coprocessor environment type.
     */
    private String getEnvironmentType(CoprocessorEnvironment env) {
        if (env instanceof MasterCoprocessorEnvironment) {
            return "Master";
        } else if (env instanceof RegionServerCoprocessorEnvironment) {
            return "RegionServer";
        } else if (env instanceof RegionCoprocessorEnvironment) {
            return "Region";
        }
        return "Unknown";
    }
}
