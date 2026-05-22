package com.grookage.hauthy.provider;

import com.grookage.hauthy.factory.DualModeSaslClientFactory;
import com.grookage.hauthy.factory.DualModeSaslServerFactory;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

import java.security.Provider;
import java.security.Security;
import java.util.concurrent.locks.ReentrantLock;

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
@SuppressWarnings({"java:S1874"}) // Using deprecated Provider constructor for Java 8 compatibility
public class HauthySecurityProvider extends Provider {

    public static final String PROVIDER_NAME = "Hauthy";
    public static final double VERSION = 1.0;
    public static final String DESCRIPTION =
            "Hauthy - Dual-mode authentication provider for HBase (Kerberos + Simple)";
    private static final long serialVersionUID = 1L;
    private static final ReentrantLock lock = new ReentrantLock();
    private static boolean registered = false;

    /**
     * Create a new HauthySecurityProvider instance.
     */
    public HauthySecurityProvider() {
        super(PROVIDER_NAME, VERSION, DESCRIPTION);

        // Register SASL server factory for all supported mechanisms
        val serverFactoryClass = DualModeSaslServerFactory.class.getName();

        put("SaslServerFactory.DUAL-MODE", serverFactoryClass);
        put("SaslServerFactory.GSSAPI", serverFactoryClass);
        put("SaslServerFactory.PLAIN", serverFactoryClass);
        put("SaslServerFactory.SIMPLE", serverFactoryClass);
        put("SaslServerFactory.ANONYMOUS", serverFactoryClass);
        put("SaslClientFactory.GSSAPI", DualModeSaslClientFactory.class.getName());

        log.debug("HauthySecurityProvider created");
    }

    /**
     * Register this provider with Java Security at the highest priority.
     *
     * <p>This method is idempotent - calling it multiple times has no effect
     * if the provider is already registered.</p>
     * <p>
     * Register and unregister do different things, hence REGISTER_LOCK, let it be.
     *
     * @return true if registration was successful, false if already registered
     */
    public static boolean register() {
        lock.lock();
        try {
            if (registered) {
                log.debug("HauthySecurityProvider already registered");
                return false;
            }

            try {
                Security.removeProvider(PROVIDER_NAME);
                val position = Security.insertProviderAt(new HauthySecurityProvider(), 1);

                if (position != -1) {
                    registered = true;
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
        } finally {
            lock.unlock();
        }
    }

    /**
     * Unregister this provider from Java Security.
     */
    public static void unregister() {
        lock.lock();
        try {
            if (!registered) {
                log.debug("HauthySecurityProvider not registered");
                return;
            }

            try {
                Security.removeProvider(PROVIDER_NAME);
                registered = false;
                log.info("Unregistered HauthySecurityProvider");
            } catch (SecurityException e) {
                log.error("Security exception unregistering HauthySecurityProvider", e);
            }
        } finally {
            lock.unlock();
        }
    }
}
