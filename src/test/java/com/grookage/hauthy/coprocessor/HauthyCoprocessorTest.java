package com.grookage.hauthy.coprocessor;

import com.grookage.hauthy.provider.HauthyInitializer;
import lombok.val;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.CoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.MasterCoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.RegionCoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.RegionServerCoprocessorEnvironment;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

public class HauthyCoprocessorTest {

    @Test
    void testHauthyProcessorCreation() {
        val copEnv = Mockito.mock(CoprocessorEnvironment.class);
        val conf = Mockito.mock(Configuration.class);
        Mockito.when(copEnv.getConfiguration()).thenReturn(conf);
        try (MockedStatic<HauthyInitializer> mockedStatic = Mockito.mockStatic(HauthyInitializer.class)) {
            val coprocessor = new HauthyCoprocessor();
            coprocessor.start(copEnv);
            Mockito.verify(copEnv).getConfiguration();
            mockedStatic.verify(() -> HauthyInitializer.initialize(conf));
            Assertions.assertNotNull(coprocessor.getMasterObserver().orElse(null));
            Assertions.assertNotNull(coprocessor.getRegionServerObserver().orElse(null));
        }
    }

    @Test
    void testHauthyProcessorFailureNoException() {
        val copEnv = Mockito.mock(CoprocessorEnvironment.class);
        val conf = Mockito.mock(Configuration.class);
        Mockito.when(copEnv.getConfiguration()).thenReturn(conf);
        val coprocessor = new HauthyCoprocessor();
        Assertions.assertDoesNotThrow(() -> coprocessor.start(copEnv));
    }

    @Test
    void testHauthyProcessorStop() {
        val copEnv = Mockito.mock(CoprocessorEnvironment.class);
        val conf = Mockito.mock(Configuration.class);
        Mockito.when(copEnv.getConfiguration()).thenReturn(conf);
        val coprocessor = new HauthyCoprocessor();
        Assertions.assertDoesNotThrow(() -> coprocessor.stop(copEnv));
    }

    @Test
    void testGetEnvironmentTypeMaster() {
        val copEnv = Mockito.mock(MasterCoprocessorEnvironment.class);
        val conf = Mockito.mock(Configuration.class);
        Mockito.when(copEnv.getConfiguration()).thenReturn(conf);

        try (MockedStatic<HauthyInitializer> ignored = Mockito.mockStatic(HauthyInitializer.class)) {
            val coprocessor = new HauthyCoprocessor();
            // start() calls getEnvironmentType() internally and logs it
            Assertions.assertDoesNotThrow(() -> coprocessor.start(copEnv));
        }
    }

    @Test
    void testGetEnvironmentTypeRegionServer() {
        val copEnv = Mockito.mock(RegionServerCoprocessorEnvironment.class);
        val conf = Mockito.mock(Configuration.class);
        Mockito.when(copEnv.getConfiguration()).thenReturn(conf);

        try (MockedStatic<HauthyInitializer> ignored = Mockito.mockStatic(HauthyInitializer.class)) {
            val coprocessor = new HauthyCoprocessor();
            // start() calls getEnvironmentType() internally and logs it
            Assertions.assertDoesNotThrow(() -> coprocessor.start(copEnv));
        }
    }

    @Test
    void testGetEnvironmentTypeRegion() {
        val copEnv = Mockito.mock(RegionCoprocessorEnvironment.class);
        val conf = Mockito.mock(Configuration.class);
        Mockito.when(copEnv.getConfiguration()).thenReturn(conf);

        try (MockedStatic<HauthyInitializer> ignored = Mockito.mockStatic(HauthyInitializer.class)) {
            val coprocessor = new HauthyCoprocessor();
            // start() calls getEnvironmentType() internally and logs it
            Assertions.assertDoesNotThrow(() -> coprocessor.start(copEnv));
        }
    }

    @Test
    void testGetEnvironmentTypeUnknown() {
        // Use base CoprocessorEnvironment which doesn't match any specific type
        val copEnv = Mockito.mock(CoprocessorEnvironment.class);
        val conf = Mockito.mock(Configuration.class);
        Mockito.when(copEnv.getConfiguration()).thenReturn(conf);

        try (MockedStatic<HauthyInitializer> ignored = Mockito.mockStatic(HauthyInitializer.class)) {
            val coprocessor = new HauthyCoprocessor();
            // start() calls getEnvironmentType() internally and logs "Unknown"
            Assertions.assertDoesNotThrow(() -> coprocessor.start(copEnv));
        }
    }

    @Test
    void testStopWithMasterEnvironment() {
        val copEnv = Mockito.mock(MasterCoprocessorEnvironment.class);
        val coprocessor = new HauthyCoprocessor();
        // stop() calls getEnvironmentType() internally
        Assertions.assertDoesNotThrow(() -> coprocessor.stop(copEnv));
    }

    @Test
    void testStopWithRegionServerEnvironment() {
        val copEnv = Mockito.mock(RegionServerCoprocessorEnvironment.class);
        val coprocessor = new HauthyCoprocessor();
        // stop() calls getEnvironmentType() internally
        Assertions.assertDoesNotThrow(() -> coprocessor.stop(copEnv));
    }

    @Test
    void testStopWithRegionEnvironment() {
        val copEnv = Mockito.mock(RegionCoprocessorEnvironment.class);
        val coprocessor = new HauthyCoprocessor();
        // stop() calls getEnvironmentType() internally
        Assertions.assertDoesNotThrow(() -> coprocessor.stop(copEnv));
    }
}
