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
package com.grookage.hauthy.factory;

import com.grookage.hauthy.core.DualModeSaslServer;
import com.grookage.hauthy.core.HauthyConfig;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.hbase.HBaseConfiguration;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Factory for creating {@link DualModeSaslServer} instances.
 *
 * <p>This factory is registered via the Java Security SPI mechanism
 * and is invoked by HBase when creating SASL servers for incoming connections.</p>
 *
 * <h3>Registration:</h3>
 * <p>The factory is automatically registered when {@link com.grookage.hauthy.provider.HauthySecurityProvider}
 * is installed.</p>
 *
 * <h3>Initialization:</h3>
 * <pre>{@code
 * // During HBase startup
 * Configuration conf = HBaseConfiguration.create();
 * Subject serverSubject = UserGroupInformation.getLoginUser().getSubject();
 * String principal = "hbase/hostname@REALM";
 *
 * DualModeSaslServerFactory.initialize(conf, serverSubject, principal);
 * }</pre>
 */
@SuppressWarnings("unused")
@Slf4j
public class DualModeSaslServerFactory implements SaslServerFactory {

    private static final String[] MECHANISMS = {
            "GSSAPI", "PLAIN", "SIMPLE", "ANONYMOUS", "DUAL-MODE"
    };

    // Shared state (initialized once per JVM)
    private static final AtomicReference<HauthyConfig> config = new AtomicReference<>();
    private static final AtomicReference<Subject> serverSubject = new AtomicReference<>();
    private static final AtomicReference<String> serverPrincipal = new AtomicReference<>();
    private static final AtomicBoolean initialized = new AtomicBoolean(false);

    private static final Object INIT_LOCK = new Object();

    /**
     * Initialize with a pre-built HauthyConfig.
     *
     * @param hauthyConfig Hauthy configuration
     * @param subject      JAAS Subject with Kerberos credentials
     * @param principal    Kerberos principal name
     */
    public static void initialize(HauthyConfig hauthyConfig, Subject subject, String principal) {
        synchronized (INIT_LOCK) {
            if (initialized.get()) {
                log.debug("DualModeSaslServerFactory already initialized");
                return;
            }

            config.set(hauthyConfig);
            serverSubject.set(subject);
            serverPrincipal.set(principal);
            initialized.set(true);

            log.info("DualModeSaslServerFactory initialized with custom config");
        }
    }

    /**
     * Check if the factory has been initialized.
     *
     * @return true if initialized
     */
    public static boolean isInitialized() {
        return initialized.get();
    }

    /**
     * Reset the factory (for testing).
     */
    public static void reset() {
        synchronized (INIT_LOCK) {
            config.set(null);
            serverSubject.set(null);
            serverPrincipal.set(null);
            initialized.set(false);
            log.info("DualModeSaslServerFactory reset");
        }
    }

    @Override
    public SaslServer createSaslServer(String mechanism,
                                       String protocol,
                                       String serverName,
                                       Map<String, ?> props,
                                       CallbackHandler cbh) {

        log.debug("createSaslServer called - mechanism: {}, protocol: {}, server: {}",
                mechanism, protocol, serverName);

        // Only handle supported mechanisms
        if (!isSupportedMechanism(mechanism)) {
            log.debug("Mechanism {} not supported by DualModeSaslServerFactory", mechanism);
            return null;
        }

        // Get configuration
        var effectiveConfig = config.get();
        if (effectiveConfig == null) {
            effectiveConfig = HauthyConfig.fromConfiguration(HBaseConfiguration.create());
        }

        // Check if dual-mode is enabled
        if (!effectiveConfig.isEnabled()) {
            log.debug("Hauthy dual-mode not enabled, returning null");
            return null;
        }

        // Create and return dual-mode SASL server
        return new DualModeSaslServer(effectiveConfig, serverPrincipal.get(), serverSubject.get(), cbh);
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
        return MECHANISMS.clone();
    }

    /**
     * Check if the given mechanism is supported by this factory.
     */
    private boolean isSupportedMechanism(String mechanism) {
        if (mechanism == null) {
            return true; // Accept null as "auto-detect"
        }
        for (String supported : MECHANISMS) {
            if (supported.equalsIgnoreCase(mechanism)) {
                return true;
            }
        }
        return false;
    }
}
