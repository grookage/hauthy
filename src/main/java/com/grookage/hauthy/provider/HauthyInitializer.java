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
package com.grookage.hauthy.provider;

import com.grookage.hauthy.core.HauthyConfig;
import com.grookage.hauthy.factory.DualModeSaslServerFactory;
import com.grookage.hauthy.metrics.AuthMetrics;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;

import javax.security.auth.Subject;
import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Main entry point for initializing Hauthy dual-mode authentication.
 *
 * <p>This class handles the complete initialization of Hauthy, including:</p>
 * <ul>
 *   <li>Loading configuration from Hadoop Configuration</li>
 *   <li>Registering the security provider</li>
 *   <li>Initializing the SASL server factory</li>
 *   <li>Setting up metrics</li>
 * </ul>
 *
 * <h3>Usage:</h3>
 * <pre>{@code
 * Configuration conf = HBaseConfiguration.create();
 * HauthyInitializer.initialize(conf);
 * }</pre>
 *
 * <h3>Configuration:</h3>
 * <p>See {@link HauthyConfig} for available configuration properties.</p>
 */
@Slf4j
@UtilityClass
public class HauthyInitializer {

    private static final AtomicBoolean initialized = new AtomicBoolean(false);
    private static final Object INIT_LOCK = new Object();

    /**
     * Initialize Hauthy dual-mode authentication.
     *
     * <p>This method is idempotent - calling it multiple times has no effect
     * after the first successful initialization.</p>
     *
     * @param conf Hadoop/HBase configuration
     * @throws IOException if initialization fails
     */
    public static void initialize(Configuration conf) throws IOException {
        synchronized (INIT_LOCK) {
            if (initialized.get()) {
                log.debug("Hauthy already initialized");
                return;
            }

            log.info("Initializing Hauthy dual-mode authentication...");

            // Load configuration
            final var config = HauthyConfig.fromConfiguration(conf);

            // Check if enabled
            if (!config.isEnabled()) {
                log.info("Hauthy dual-mode authentication is disabled");
                return;
            }

            // Validate configuration
            config.validate();

            try {
                // Register security provider
                final var providerRegistered = HauthySecurityProvider.register();
                if (providerRegistered) {
                    log.info("Registered HauthySecurityProvider");
                }

                // Get Kerberos credentials if available
                Subject serverSubject = null;
                String serverPrincipal = null;

                if (UserGroupInformation.isSecurityEnabled()) {
                    try {
                        final var ugi = UserGroupInformation.getLoginUser();
                        serverPrincipal = ugi.getUserName();
                        //noinspection removal - Using deprecated API for Java 17 compatibility
                        serverSubject = ugi.doAs((PrivilegedAction<Subject>) () -> Subject.getSubject(AccessController.getContext()));
                        log.info("Using Kerberos principal: {}", serverPrincipal);
                    } catch (IOException e) {
                        log.warn("Failed to get login user for Kerberos", e);
                        if (config.isAllowKerberos() && !config.isAllowSimple()) {
                            throw new IOException("Kerberos required but login failed", e);
                        }
                    }
                } else {
                    log.warn("Hadoop security not enabled - only simple auth will work");
                }

                // Initialize factory
                DualModeSaslServerFactory.initialize(config, serverSubject, serverPrincipal);

                // Initialize metrics
                AuthMetrics.getInstance();

                initialized.set(true);
                log.info("Hauthy dual-mode authentication initialized successfully");
                log.info("  - Allow Simple: {}", config.isAllowSimple());
                log.info("  - Allow Kerberos: {}", config.isAllowKerberos());
                log.info("  - Metrics enabled: {}", config.isMetricsEnabled());

            } catch (Exception e) {
                log.error("Failed to initialize Hauthy", e);
                throw new IOException("Hauthy initialization failed", e);
            }
        }
    }

    /**
     * Check if Hauthy has been initialized.
     *
     * @return true if initialized
     */
    @SuppressWarnings("unused")
    public static boolean isInitialized() {
        return initialized.get();
    }

    /**
     * Get the current authentication metrics.
     *
     * @return AuthMetrics instance, or null if not initialized
     */
    public static AuthMetrics getMetrics() {
        if (!initialized.get()) {
            return null;
        }
        return AuthMetrics.getInstance();
    }

    /**
     * Shutdown Hauthy (for testing or graceful shutdown).
     */
    @SuppressWarnings("unused")
    public static void shutdown() {
        synchronized (INIT_LOCK) {
            if (!initialized.get()) {
                return;
            }

            log.info("Shutting down Hauthy...");

            HauthySecurityProvider.unregister();
            DualModeSaslServerFactory.reset();

            initialized.set(false);
            log.info("Hauthy shut down");
        }
    }
}
