package com.grookage.hauthy.core;

import com.grookage.hauthy.metrics.AuthMetrics;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Dual-mode SASL client for ZooKeeper connections that enables replication between
 * Kerberos and non-Kerberos clusters.
 *
 * <p>When an NB6 (Kerberos) HBase RS connects to MH6 (non-Kerberos) ZK as a
 * replication peer, the JVM's JAAS {@code Client} section causes the ZK client to
 * attempt GSSAPI auth. The de-Kerberized ZK's service principal no longer exists in
 * KDC, so {@code evaluateChallenge} throws KDC error 7
 * ({@code KDC_ERR_S_PRINCIPAL_UNKNOWN}).</p>
 *
 * <p>This client wraps the real SunSASL {@code GssKrb5Client} and falls back to a
 * no-op exchange when the server principal is missing from KDC (error code 7 only).
 * All other GSSAPI errors (expired credentials, clock skew, etc.) propagate normally
 * so they are not silently swallowed.</p>
 *
 * <h3>No-op exchange flow:</h3>
 * <ol>
 *   <li>First {@code evaluateChallenge} catches KDC error 7, switches to no-op mode,
 *       returns {@code new byte[0]} (empty initial token)</li>
 *   <li>Client sends empty token to target ZK server</li>
 *   <li>Target ZK server (with {@code allowSaslFailedClients=true}) responds with
 *       null/empty token and allows the session</li>
 *   <li>Client receives server response, returns {@code null}, marks complete</li>
 *   <li>ZK session established without authentication</li>
 * </ol>
 *
 * <p>When connecting to a Kerberos ZK (server principal exists in KDC), real GSSAPI
 * is used without any fallback — behaviour is identical to stock SunSASL.</p>
 *
 * <p><strong>Prerequisite:</strong> the target non-Kerberos ZK must have
 * {@code allowSaslFailedClients=true} in {@code zoo.cfg}.</p>
 *
 * @see DualModeSaslServer#createNativeGssapiServer  — same provider-skipping pattern
 */
@Slf4j
public class DualModeSaslClient implements SaslClient {

    private static final String MECHANISM_GSSAPI = "GSSAPI";
    private final SaslClient realGssapiClient;
    private final AtomicReference<NoOpState> noOpState = new AtomicReference<>();
    private final AtomicBoolean complete = new AtomicBoolean(false);

    /**
     * Create a new DualModeSaslClient.
     *
     * <p>Attempts to create the underlying native GSSAPI client immediately.
     * If the native factory cannot be found (unusual), switches to no-op mode
     * pre-emptively.</p>
     */
    public DualModeSaslClient(String authorizationId,
                              String protocol,
                              String serverName,
                              Map<String, ?> props,
                              CallbackHandler cbh) {
        SaslClient client = null;
        try {
            client = createNativeGssapiClient(authorizationId, protocol, serverName, props, cbh);
        } catch (SaslException e) {
            // Native factory unavailable — this is unusual; the real KDC failure happens
            // later in evaluateChallenge, not here. Pre-emptively set no-op so the
            // caller does not get a NullPointerException.
            log.warn("Could not instantiate native GSSAPI SaslClient ({}); will use no-op mode immediately",
                    e.getMessage());
            noOpState.set(NoOpState.PENDING);
        }
        this.realGssapiClient = client;
    }

    @Override
    public String getMechanismName() {
        return MECHANISM_GSSAPI;
    }

    /**
     * GSSAPI always has an initial response; so does our no-op mode.
     */
    @Override
    public boolean hasInitialResponse() {
        if (noOpState.get() != null || realGssapiClient == null) {
            return true;
        }
        return realGssapiClient.hasInitialResponse();
    }

    /**
     * Evaluate the server challenge.
     *
     * <p>On the first call, delegates to the real GSSAPI client. If that call throws
     * a {@link SaslException} whose cause chain contains KDC error 7
     * ("Server not found in Kerberos database"), switches to no-op mode and returns
     * an empty byte array as the initial token. All other exceptions propagate
     * unchanged.</p>
     */
    @Override
    public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
        if (noOpState.get() != null || realGssapiClient == null) {
            if (noOpState.get() == null) {
                noOpState.set(NoOpState.PENDING);
            }
            return stepNoOp();
        }

        try {
            val response = realGssapiClient.evaluateChallenge(challenge);
            if (realGssapiClient.isComplete()) {
                complete.set(true);
            }
            return response;
        } catch (SaslException e) {
            if (isServerNotFoundInKdc(e)) {
                log.warn("GSSAPI KDC lookup failed: target ZK server principal not found in KDC " +
                        "(KDC_ERR_S_PRINCIPAL_UNKNOWN / error 7). " +
                        "Falling back to no-op ZK SASL exchange — " +
                        "requires allowSaslFailedClients=true on the target ZooKeeper.");
                AuthMetrics.getInstance().recordZkSaslNoOpFallback();
                disposeRealClient(); // release half-initialized GSSContext
                noOpState.set(NoOpState.PENDING);
                return stepNoOp();
            }
            throw e;
        }
    }

    /**
     * Advance the no-op state machine.
     *
     * <ul>
     *   <li>PENDING → INITIAL_SENT: return empty byte array (the initial token sent to server)</li>
     *   <li>INITIAL_SENT → DONE: server responded; return null to tell ZK client no more tokens</li>
     *   <li>DONE: return null</li>
     * </ul>
     *
     * <p>Note: returning {@code null} in INITIAL_SENT/DONE is intentional SASL protocol
     * semantics — it signals "no token to send" to the ZK client, preventing unnecessary
     * empty packets. Returning {@code new byte[0]} would cause the client to send an
     * additional empty SASL packet to the server.</p>
     */
    @SuppressWarnings("java:S1168") // null return is intentional SASL protocol signal (no token to send)
    private byte[] stepNoOp() {
        val currentState = noOpState.get();
        switch (currentState) {
            case PENDING:
                noOpState.set(NoOpState.INITIAL_SENT);
                complete.set(true);
                log.debug("No-op SASL: sent empty initial token");
                return new byte[0];
            case INITIAL_SENT:
                noOpState.set(NoOpState.DONE);
                log.debug("No-op SASL: exchange complete");
                return null;
            case DONE:
                log.debug("No-op SASL: already complete, returning null");
                return null;
            default:
                throw new IllegalStateException("Unknown NoOpState: " + currentState);
        }
    }

    @Override
    public boolean isComplete() {
        return complete.get();
    }

    /**
     * Unwrap incoming data. In no-op mode, returns data unchanged (no encryption).
     *
     * @param incoming the incoming byte array
     * @param offset   the offset in the array
     * @param len      the length of data to unwrap
     * @return unwrapped data, or copy of input in no-op mode
     * @throws SaslException if unwrapping fails
     */
    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
        if (noOpState.get() != null || realGssapiClient == null) {
            return Arrays.copyOfRange(incoming, offset, offset + len);
        }
        return realGssapiClient.unwrap(incoming, offset, len);
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
        if (noOpState.get() != null || realGssapiClient == null) {
            return Arrays.copyOfRange(outgoing, offset, offset + len);
        }
        return realGssapiClient.wrap(outgoing, offset, len);
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        if (noOpState.get() != null || realGssapiClient == null) {
            return null;
        }
        return realGssapiClient.getNegotiatedProperty(propName);
    }

    @Override
    public void dispose() {
        disposeRealClient();
    }

    /**
     * Safely dispose the real GSSAPI client (release GSSContext, credentials).
     * Called both on fallback transition and on normal dispose.
     */
    private void disposeRealClient() {
        if (realGssapiClient != null) {
            try {
                realGssapiClient.dispose();
            } catch (SaslException e) {
                log.debug("Error disposing real GSSAPI client (non-fatal): {}", e.getMessage());
            }
        }
    }

    /**
     * Walk the exception cause chain looking for KDC error 7
     * (KDC_ERR_S_PRINCIPAL_UNKNOWN — server principal not in database).
     *
     * <p>We are deliberately narrow: only this error triggers the no-op fallback.
     * Credential expiry (24), clock skew (37), bad keytab, etc. are real problems
     * that must propagate so they are not silently ignored.</p>
     */
    private boolean isServerNotFoundInKdc(SaslException e) {
        Throwable cause = e;
        while (cause != null) {
            val msg = cause.getMessage();
            if (msg != null && (
                    msg.contains("Server not found in Kerberos database") ||
                            msg.contains("LOOKING_UP_SERVER") ||
                            msg.contains("KDC_ERR_S_PRINCIPAL_UNKNOWN"))) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

    /**
     * Create a native GSSAPI {@link SaslClient} by iterating the JVM's security
     * provider list and skipping Hauthy's own provider to avoid infinite recursion.
     *
     * <p>Mirrors {@code DualModeSaslServer.createNativeGssapiServer()} exactly;
     * keep the provider-name check ({@code "Hauthy"}) in sync with
     * {@link com.grookage.hauthy.provider.HauthySecurityProvider#PROVIDER_NAME}.</p>
     */
    private SaslClient createNativeGssapiClient(String authorizationId,
                                                String protocol,
                                                String serverName,
                                                Map<String, ?> props,
                                                CallbackHandler cbh) throws SaslException {
        for (Provider p : Security.getProviders("SaslClientFactory.GSSAPI")) {
            if ("Hauthy".equalsIgnoreCase(p.getName())) {
                log.debug("Skipping Hauthy provider for native GSSAPI client creation to avoid recursion");
                continue;
            }
            val client = createClientFromProvider(p, authorizationId, protocol, serverName, props, cbh);
            if (client != null) {
                return client;
            }
        }
        throw new SaslException(
                "No native GSSAPI SaslClientFactory found (all providers excluding Hauthy were tried)");
    }

    /**
     * Attempt to create a GSSAPI {@link SaslClient} from a single provider.
     *
     * @return a valid SaslClient, or {@code null} if this provider cannot produce one
     */
    private SaslClient createClientFromProvider(Provider p,
                                                String authorizationId,
                                                String protocol,
                                                String serverName,
                                                Map<String, ?> props,
                                                CallbackHandler cbh) {
        val service = p.getService("SaslClientFactory", MECHANISM_GSSAPI);
        if (service == null) {
            return null;
        }
        try {
            val factory = (SaslClientFactory) service.newInstance(null);
            val client = factory.createSaslClient(
                    new String[]{MECHANISM_GSSAPI}, authorizationId, protocol, serverName, props, cbh);
            if (client != null) {
                log.debug("Created native GSSAPI SaslClient using provider: {}", p.getName());
            }
            return client;
        } catch (Exception ex) {
            log.debug("Provider {} failed to create GSSAPI client: {}", p.getName(), ex.getMessage());
            return null;
        }
    }

    /**
     * No-op handshake state machine.
     *
     * <ul>
     *   <li>{@code PENDING} — about to send the first (empty) token</li>
     *   <li>{@code INITIAL_SENT} — empty token sent, waiting for server response</li>
     *   <li>{@code DONE} — server responded, exchange complete</li>
     * </ul>
     */
    private enum NoOpState {
        PENDING, INITIAL_SENT, DONE
    }
}
