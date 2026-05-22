package com.grookage.hauthy.coprocessor;

import com.grookage.hauthy.provider.HauthyInitializer;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
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
 */
@Slf4j
public class HauthyCoprocessor implements MasterCoprocessor, RegionServerCoprocessor,
        MasterObserver, RegionServerObserver {

    private static final String MASTER_ENV = "Master";
    private static final String REGIONSERVER_ENV = "RegionServer";
    private static final String REGION_ENV = "Region";
    private static final String UNKNOWN_ENV = "Unknown";

    @Override
    public void start(CoprocessorEnvironment env) {
        log.info("HauthyCoprocessor starting on {}", getEnvironmentType(env));
        val conf = env.getConfiguration();
        try {
            HauthyInitializer.initialize(conf);
            log.info("HauthyCoprocessor started successfully");
        } catch (Exception e) {
            log.error("Failed to initialize Hauthy in coprocessor. Starting Hbase without the CoProcessor", e);
        }
    }

    // Don't shutdown Hauthy here - other coprocessors might still need it
    // Hauthy will be cleaned up when JVM exits
    @Override
    public void stop(CoprocessorEnvironment env) {
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

    private String getEnvironmentType(CoprocessorEnvironment<?> env) {
        if (env instanceof MasterCoprocessorEnvironment) {
            return MASTER_ENV;
        } else if (env instanceof RegionServerCoprocessorEnvironment) {
            return REGIONSERVER_ENV;
        } else if (env instanceof RegionCoprocessorEnvironment) {
            return REGION_ENV;
        }
        return UNKNOWN_ENV;
    }
}
