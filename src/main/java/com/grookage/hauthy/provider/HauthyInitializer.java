package com.grookage.hauthy.provider;

import com.grookage.hauthy.core.HauthyConfig;
import com.grookage.hauthy.factory.DualModeSaslServerFactory;
import com.grookage.hauthy.metrics.AuthMetrics;
import lombok.Getter;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;

import javax.security.auth.Subject;
import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.concurrent.locks.ReentrantLock;

@SuppressWarnings("unused")
@Slf4j
@UtilityClass
public class HauthyInitializer {

    private static final ReentrantLock lock = new ReentrantLock();
    @Getter
    private static boolean initialized = false;

    /**
     * Get the current authentication metrics.
     *
     * @return AuthMetrics instance, or null if not initialized
     */
    public static AuthMetrics getMetrics() {
        if (!isInitialized()) {
            return null;
        }
        return AuthMetrics.getInstance();
    }

    /**
     * Shutdown Hauthy (for testing or graceful shutdown).
     */
    public static void shutdown() {
        lock.lock();
        try {
            if (!isInitialized()) {
                return;
            }

            log.info("Shutting down Hauthy...");

            HauthySecurityProvider.unregister();
            DualModeSaslServerFactory.reset();

            initialized = false;
            log.info("Hauthy shut down");
        } finally {
            lock.unlock();
        }
    }

    private static void initializeFactory(HauthyConfig config) throws IOException {
        Subject serverSubject = null;
        String serverPrincipal = null;

        if (UserGroupInformation.isSecurityEnabled()) {
            try {
                val ugi = UserGroupInformation.getLoginUser();
                // Get subject via doAs to work around protected access in older Hadoop versions
                serverSubject = ugi.doAs((PrivilegedAction<Subject>) () ->
                        Subject.getSubject(AccessController.getContext()));
                serverPrincipal = ugi.getUserName();
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
        DualModeSaslServerFactory.initialize(config, serverSubject, serverPrincipal);
    }

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
        lock.lock();
        try {
            if (isInitialized()) {
                log.debug("Hauthy already initialized");
                return;
            }

            log.info("Initializing Hauthy dual-mode authentication...");

            val config = HauthyConfig.fromConfiguration(conf);
            if (!config.isEnabled()) {
                log.info("Hauthy dual-mode authentication is disabled");
                return;
            }
            config.validate();

            try {
                // Register security provider
                val providerRegistered = HauthySecurityProvider.register();
                if (providerRegistered) {
                    log.info("Registered HauthySecurityProvider");
                }

                initializeFactory(config);
                initialized = true;
                log.info("Hauthy dual-mode authentication initialized successfully");
                log.info("  - Allow Simple: {}", config.isAllowSimple());
                log.info("  - Allow Kerberos: {}", config.isAllowKerberos());
                log.info("  - Metrics enabled: {}", config.isMetricsEnabled());

            } catch (Exception e) {
                log.error("Failed to initialize Hauthy", e);
                throw new IOException("Hauthy initialization failed", e);
            }
        } finally {
            lock.unlock();
        }
    }
}
