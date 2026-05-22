package com.grookage.hauthy.factory;

import com.grookage.hauthy.core.DualModeSaslServer;
import com.grookage.hauthy.core.HauthyConfig;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.hadoop.hbase.HBaseConfiguration;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Factory for creating {@link com.grookage.hauthy.core.DualModeSaslServer} instances.
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
@Slf4j
public class DualModeSaslServerFactory implements SaslServerFactory {

    private static final String[] MECHANISMS = {
            "GSSAPI", "PLAIN", "SIMPLE", "ANONYMOUS", "DUAL-MODE"
    };

    private static final ReentrantLock lock = new ReentrantLock();
    private static HauthyConfig config;
    private static Subject serverSubject;
    private static String serverPrincipal;
    private static boolean initialized = false;

    /**
     * Initialize with a pre-built HauthyConfig.
     *
     * @param hauthyConfig Hauthy configuration
     * @param subject      JAAS Subject with Kerberos credentials
     * @param principal    Kerberos principal name
     */
    public static void initialize(HauthyConfig hauthyConfig, Subject subject, String principal) {
        lock.lock();
        try {
            if (initialized) {
                log.debug("DualModeSaslServerFactory already initialized");
                return;
            }

            config = hauthyConfig;
            serverSubject = subject;
            serverPrincipal = principal;
            initialized = true;

            log.info("DualModeSaslServerFactory initialized with custom config");
        } finally {
            lock.unlock();
        }
    }

    /**
     * Reset the factory (for testing).
     */
    public static void reset() {
        lock.lock();
        try {
            config = null;
            serverSubject = null;
            serverPrincipal = null;
            initialized = false;
            log.info("DualModeSaslServerFactory reset");
        } finally {
            lock.unlock();
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
        if (!isSupportedMechanism(mechanism)) {
            log.debug("Mechanism {} not supported by DualModeSaslServerFactory", mechanism);
            return null;
        }
        lock.lock();
        try {
            val effectiveConfig = null != config ? config
                    : HauthyConfig.fromConfiguration(HBaseConfiguration.create());
            if (!effectiveConfig.isEnabled()) {
                log.debug("Hauthy dual-mode not enabled, returning null");
                return null;
            }
            return new DualModeSaslServer(effectiveConfig, serverPrincipal, serverSubject, cbh);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
        return MECHANISMS.clone();
    }

    /**
     * Check if the given mechanism is supported by this factory.
     */
    private boolean isSupportedMechanism(String mechanism) {
        return mechanism == null ||
                Arrays.stream(MECHANISMS)
                        .anyMatch(supported ->
                                supported.equalsIgnoreCase(mechanism)); // Accept null as "auto-detect"
    }
}
