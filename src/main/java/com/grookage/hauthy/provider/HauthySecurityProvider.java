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

import com.grookage.hauthy.factory.DualModeSaslServerFactory;
import lombok.extern.slf4j.Slf4j;

import java.io.Serial;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Java Security Provider that registers Hauthy's SASL factory.
 *
 * <p>This provider registers the {@link DualModeSaslServerFactory} with Java's
 * security infrastructure, making it available for SASL server creation.</p>
 *
 * <h3>Registration:</h3>
 * <pre>{@code
 * // Option 1: Static registration
 * HauthySecurityProvider.register();
 *
 * // Option 2: Manual registration
 * Security.insertProviderAt(new HauthySecurityProvider(), 1);
 * }</pre>
 *
 * <h3>Automatic Registration:</h3>
 * <p>The provider can be automatically registered by adding it to the
 * {@code java.security.Provider} service file or JVM security properties.</p>
 */
@Slf4j
public class HauthySecurityProvider extends Provider {

    public static final String PROVIDER_NAME = "Hauthy";
    public static final double VERSION = 1.0;
    public static final String DESCRIPTION =
            "Hauthy - Dual-mode authentication provider for HBase (Kerberos + Simple)";
    @Serial
    private static final long serialVersionUID = 1L;
    private static final AtomicBoolean registered = new AtomicBoolean(false);
    private static final Object REGISTER_LOCK = new Object();

    @SuppressWarnings("deprecation")
    public HauthySecurityProvider() {
        super(PROVIDER_NAME, VERSION, DESCRIPTION);

        // Register SASL server factory for all supported mechanisms
        final var factoryClass = DualModeSaslServerFactory.class.getName();

        put("SaslServerFactory.DUAL-MODE", factoryClass);
        put("SaslServerFactory.GSSAPI", factoryClass);
        put("SaslServerFactory.PLAIN", factoryClass);
        put("SaslServerFactory.SIMPLE", factoryClass);
        put("SaslServerFactory.ANONYMOUS", factoryClass);

        log.debug("HauthySecurityProvider created");
    }

    /**
     * Register this provider with Java Security at the highest priority.
     *
     * <p>This method is idempotent - calling it multiple times has no effect
     * if the provider is already registered.</p>
     *
     * @return true if registration was successful, false if already registered
     */
    public static boolean register() {
        synchronized (REGISTER_LOCK) {
            if (registered.get()) {
                log.debug("HauthySecurityProvider already registered");
                return false;
            }

            try {
                // Remove existing provider if present
                Security.removeProvider(PROVIDER_NAME);

                // Insert at position 1 (highest priority)
                final var position = Security.insertProviderAt(new HauthySecurityProvider(), 1);

                if (position != -1) {
                    registered.set(true);
                    log.info("Registered HauthySecurityProvider at position {}", position);
                    return true;
                } else {
                    log.warn("Failed to register HauthySecurityProvider");
                    return false;
                }
            } catch (SecurityException e) {
                log.error("Security exception registering HauthySecurityProvider", e);
                return false;
            }
        }
    }

    /**
     * Unregister this provider from Java Security.
     */
    public static void unregister() {
        synchronized (REGISTER_LOCK) {
            if (!registered.get()) {
                log.debug("HauthySecurityProvider not registered");
                return;
            }

            try {
                Security.removeProvider(PROVIDER_NAME);
                registered.set(false);
                log.info("Unregistered HauthySecurityProvider");
            } catch (SecurityException e) {
                log.error("Security exception unregistering HauthySecurityProvider", e);
            }
        }
    }

    /**
     * Check if the provider is currently registered.
     *
     * @return true if registered
     */
    @SuppressWarnings("unused")
    public static boolean isRegistered() {
        return Security.getProvider(PROVIDER_NAME) != null;
    }
}
