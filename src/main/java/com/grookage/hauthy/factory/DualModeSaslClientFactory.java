package com.grookage.hauthy.factory;

import com.grookage.hauthy.core.DualModeSaslClient;
import com.grookage.hauthy.core.HauthyConfig;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.hbase.HBaseConfiguration;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import java.util.Arrays;
import java.util.Map;

/**
 * Factory for creating {@link DualModeSaslClient} instances.
 *
 * <p>Registered via {@link com.grookage.hauthy.provider.HauthySecurityProvider}
 * as the {@code SaslClientFactory.GSSAPI} service. Because Hauthy is inserted at
 * position 1 in the JVM provider list, this factory is invoked before SunSASL when
 * any code calls {@code Sasl.createSaslClient("GSSAPI", ...)}.</p>
 *
 * <p>The no-op fallback is gated by {@code hauthy.zk.sasl.fallback=true} in
 * hbase-site.xml. When disabled (default), this factory returns {@code null} for
 * GSSAPI, letting SunSASL handle it normally — no behaviour change from stock JVM.</p>
 *
 * <p>This enables cross-cluster ZooKeeper connections between Kerberos and
 * non-Kerberos HBase clusters during zero-downtime Kerberos migration. See
 * {@link DualModeSaslClient} for the full exchange protocol.</p>
 */
@Slf4j
public class DualModeSaslClientFactory implements SaslClientFactory {

    private static final String MECHANISM_GSSAPI = "GSSAPI";
    private static final String[] MECHANISMS = {MECHANISM_GSSAPI};

    @Override
    public SaslClient createSaslClient(String[] mechanisms,
                                       String authorizationId,
                                       String protocol,
                                       String serverName,
                                       Map<String, ?> props,
                                       CallbackHandler cbh) {
        if (!Arrays.asList(mechanisms).contains(MECHANISM_GSSAPI)) {
            return null;
        }

        if (!isZkSaslFallbackEnabled()) {
            // Fallback disabled — return null so SunSASL handles it (stock behaviour)
            return null;
        }

        log.debug("DualModeSaslClientFactory creating DualModeSaslClient for {}:{}",
                protocol, serverName);
        return new DualModeSaslClient(authorizationId, protocol, serverName, props, cbh);
    }


    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
        return MECHANISMS.clone();
    }

    /**
     * Check if the ZK SASL fallback is enabled in HBase configuration.
     * Reads {@code hauthy.zk.sasl.fallback} (default: false).
     */
    private boolean isZkSaslFallbackEnabled() {
        try {
            return HBaseConfiguration.create()
                    .getBoolean(HauthyConfig.ZK_SASL_FALLBACK, false);
        } catch (Exception e) {
            log.debug("Could not read HBase config for zk.sasl.fallback, defaulting to false");
            return false;
        }
    }
}
