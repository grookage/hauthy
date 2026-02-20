package com.grookage.hauthy.coprocessor;

import com.grookage.hauthy.provider.HauthyInitializer;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.CoprocessorEnvironment;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

public class HauthyCoprocessorTest {

    @Test
    void testHauthyProcessorCreation() {
        final var copEnv = Mockito.mock(CoprocessorEnvironment.class);
        final var conf = Mockito.mock(Configuration.class);
        Mockito.when(copEnv.getConfiguration()).thenReturn(conf);
        try (MockedStatic<HauthyInitializer> mockedStatic = Mockito.mockStatic(HauthyInitializer.class)) {
            final var coprocessor = new HauthyCoprocessor();
            coprocessor.start(copEnv);
            Mockito.verify(copEnv).getConfiguration();
            mockedStatic.verify(() -> HauthyInitializer.initialize(conf));
            Assertions.assertNotNull(coprocessor.getMasterObserver().orElse(null));
            Assertions.assertNotNull(coprocessor.getRegionServerObserver().orElse(null));
        }
    }

    @Test
    void testHauthyProcessorFailureNoException() {
        final var copEnv = Mockito.mock(CoprocessorEnvironment.class);
        final var conf = Mockito.mock(Configuration.class);
        Mockito.when(copEnv.getConfiguration()).thenReturn(conf);
        final var coprocessor = new HauthyCoprocessor();
        Assertions.assertDoesNotThrow(() -> coprocessor.start(copEnv));
    }

    @Test
    void testHauthyProcessorStop() {
        final var copEnv = Mockito.mock(CoprocessorEnvironment.class);
        final var conf = Mockito.mock(Configuration.class);
        Mockito.when(copEnv.getConfiguration()).thenReturn(conf);
        final var coprocessor = new HauthyCoprocessor();
        Assertions.assertDoesNotThrow(() -> coprocessor.stop(copEnv));
    }
}
