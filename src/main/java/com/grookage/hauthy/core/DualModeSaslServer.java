package com.grookage.hauthy.core;

import com.grookage.hauthy.metrics.AuthMetrics;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.nio.charset.StandardCharsets;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Dual-mode SASL server that accepts both Kerberos (GSSAPI) and Simple authentication.
 *
 * <p>This enables zero-downtime migration from simple to Kerberos authentication
 * by allowing both authentication methods simultaneously during the migration window.</p>
 *
 * <h3>Usage:</h3>
 * <pre>{@code
 * HauthyConfig config = HauthyConfig.builder()
 *     .enabled(true)
 *     .allowSimple(true)
 *     .allowKerberos(true)
 *     .build();
 *
 * DualModeSaslServer server = new DualModeSaslServer(
 *     config, serverPrincipal, serverSubject, callbackHandler);
 * server.setClientAddress("10.0.1.100");
 *
 * byte[] challenge = server.evaluateResponse(clientResponse);
 * }</pre>
 *
 * <h3>Security Considerations:</h3>
 * <ul>
 *   <li>During migration, simple auth clients can access the cluster</li>
 *   <li>Monitor {@link AuthMetrics} to track migration progress</li>
 *   <li>Disable simple auth once all clients have migrated</li>
 *   <li>Use host restrictions to limit simple auth exposure</li>
 * </ul>
 *
 * @see HauthyConfig
 * @see AuthMetrics
 */
@Slf4j
public class DualModeSaslServer implements SaslServer {

    // SASL mechanism constants
    private static final String MECHANISM_GSSAPI = "GSSAPI";

    // Configuration
    private final HauthyConfig config;
    private final String serverPrincipal;
    private final Subject serverSubject;
    private final CallbackHandler callbackHandler;
    // Metrics
    private final AuthMetrics metrics;
    // State
    private final AtomicReference<SaslServer> delegateSaslServer = new AtomicReference<>();
    private final AtomicReference<AuthMode> selectedAuthMode = new AtomicReference<>();
    private final AtomicReference<String> authorizationId = new AtomicReference<>();
    private final AtomicBoolean isComplete = new AtomicBoolean(false);
    @Getter
    private boolean simpleMode = false;
    @Setter
    @Getter
    private String clientAddress;

    /**
     * Create a new dual-mode SASL server.
     *
     * @param config          Hauthy configuration
     * @param serverPrincipal Kerberos principal for this server (can be null if Kerberos disabled)
     * @param serverSubject   JAAS subject with Kerberos credentials (can be null if Kerberos disabled)
     * @param callbackHandler Callback handler for authentication
     */
    public DualModeSaslServer(HauthyConfig config,
                              String serverPrincipal,
                              Subject serverSubject,
                              CallbackHandler callbackHandler) {
        this.config = config;
        this.serverPrincipal = serverPrincipal;
        this.serverSubject = serverSubject;
        this.callbackHandler = callbackHandler;
        this.metrics = AuthMetrics.getInstance();

        log.debug("DualModeSaslServer created - allowSimple: {}, allowKerberos: {}",
                config.isAllowSimple(), config.isAllowKerberos());
    }

    public AuthMode getSelectedAuthMode() {
        return selectedAuthMode.get();
    }

    @Override
    public byte[] evaluateResponse(byte[] response) throws SaslException {
        try {
            return null == delegateSaslServer.get() ?
                    handleInitialResponse(response) : delegateEvaluateResponse(response);
        } catch (SaslException e) {
            log.error("SASL evaluation failed for client {}: {}", clientAddress, e.getMessage());
            throw e;
        }
    }

    /**
     * Handle the initial SASL response to determine authentication mode.
     */
    private byte[] handleInitialResponse(byte[] response) throws SaslException {
        // Determine which authentication mode the client is using
        val requestedMode = detectAuthMode(response);
        log.debug("Client {} requesting auth mode: {}", clientAddress, requestedMode);

        // Validate the requested mode is allowed
        validateAuthMode(requestedMode);
        this.selectedAuthMode.set(requestedMode);

        // Create the appropriate SASL server
        switch (requestedMode) {
            case KERBEROS:
                return initKerberosAuth(response);
            case SIMPLE:
            case ANONYMOUS:
                return initSimpleAuth(response);
            default:
                throw new SaslException("Unknown auth mode: " + requestedMode);
        }
    }

    /**
     * Detect authentication mode from the initial client message.
     *
     * <p>HBase RPC protocol sends a connection header that indicates the auth method.
     * We parse this to determine if the client wants Kerberos or Simple auth.</p>
     *
     * @param response initial client response
     * @return detected AuthMode
     */
    private AuthMode detectAuthMode(byte[] response) {
        if (response == null || response.length == 0) {
            return AuthMode.SIMPLE;
        }
        return isGssapiToken(response) ? AuthMode.KERBEROS : AuthMode.SIMPLE;
    }

    /**
     * Detect GSSAPI token by checking ASN.1 structure.
     * GSSAPI tokens: APPLICATION 0 SEQUENCE (0x60) with valid length encoding.
     */
    private boolean isGssapiToken(byte[] data) {
        if (data.length < 2 || (data[0] & 0xFF) != 0x60) {
            return false;
        }

        // Validate ASN.1 length encoding
        val lengthByte = data[1] & 0xFF;
        if (lengthByte < 0x80) {
            // Short form: length byte is the length
            return data.length >= 2 + lengthByte;
        } else if (lengthByte == 0x80) {
            // Indefinite length - valid for GSSAPI
            return true;
        } else {
            // Long form: lower 7 bits = number of length bytes
            int numLengthBytes = lengthByte & 0x7F;
            return data.length > 1 + numLengthBytes;
        }
    }

    /**
     * Validate that the requested auth mode is allowed by configuration.
     */
    private void validateAuthMode(AuthMode mode) throws SaslException {
        switch (mode) {
            case KERBEROS:
                if (!config.isAllowKerberos()) {
                    metrics.recordKerberosFailure();
                    throw new SaslException("Kerberos authentication is disabled");
                }
                break;

            case SIMPLE:
            case ANONYMOUS:
                if (!config.isAllowSimple()) {
                    metrics.recordSimpleRejected();
                    log.warn("Simple auth rejected for client {} - simple auth is disabled",
                            clientAddress);
                    throw new SaslException(
                            "Simple authentication is disabled. Please use Kerberos authentication.");
                }

                if (!config.isSimpleAuthAllowedForHost(clientAddress)) {
                    metrics.recordSimpleRejected();
                    log.warn("Simple auth rejected for client {} - host not in allowed list",
                            clientAddress);
                    throw new SaslException(
                            "Simple authentication not allowed from this host. Use Kerberos.");
                }
                break;

            default:
                throw new SaslException("Unknown auth mode: " + mode);
        }
    }

    /**
     * Initialize Kerberos (GSSAPI) authentication.
     *
     * <p>IMPORTANT: must use {@link #createNativeGssapiServer} rather than
     * {@code Sasl.createSaslServer("GSSAPI", ...)} here. Because Hauthy registers
     * itself as the highest-priority SaslServerFactory.GSSAPI provider, calling
     * Sasl.createSaslServer("GSSAPI") would recurse back into DualModeSaslServer,
     * causing infinite recursion and a StackOverflowError.</p>
     */
    private byte[] initKerberosAuth(byte[] response) throws SaslException {
        log.debug("Initializing Kerberos auth for client {}", clientAddress);

        try {
            if (serverSubject != null) {
                delegateSaslServer.set(Subject.doAs(serverSubject,
                        (PrivilegedExceptionAction<SaslServer>) () ->
                                createNativeGssapiServer(getServerName(), callbackHandler)));
            } else {
                log.warn("No server subject available for Kerberos auth");
                delegateSaslServer.set(createNativeGssapiServer(getServerName(), callbackHandler));
            }

            if (delegateSaslServer.get() == null) {
                metrics.recordKerberosFailure();
                throw new SaslException("Failed to create GSSAPI SASL server: no provider available");
            }

            this.simpleMode = false;
            return delegateEvaluateResponse(response);
        } catch (PrivilegedActionException e) {
            metrics.recordKerberosFailure();
            val cause = e.getCause();
            throw new SaslException("Failed to create Kerberos SASL server: " +
                    (cause != null ? cause.getMessage() : e.getMessage()), cause);
        } catch (SaslException e) {
            metrics.recordKerberosFailure();
            throw e;
        }
    }

    /**
     * Create a native GSSAPI SaslServer by explicitly skipping Hauthy's own provider.
     *
     * <p>Hauthy registers itself as {@code SaslServerFactory.GSSAPI} at position 1.
     * If we used {@code Sasl.createSaslServer("GSSAPI", ...)} here, the JVM would
     * pick Hauthy's factory again, creating another DualModeSaslServer as the delegate,
     * which would again call this method — infinite recursion. We avoid this by
     * iterating the provider list and skipping any provider named "Hauthy".</p>
     */
    /**
     * Create a native GSSAPI SaslServer by explicitly skipping Hauthy's own provider.
     */
    private SaslServer createNativeGssapiServer(String serverName,
                                                CallbackHandler cbh) throws SaslException {
        val props = new HashMap<String, String>();
        props.put(Sasl.QOP, "auth-conf,auth-int,auth");
        props.put(Sasl.SERVER_AUTH, "true");

        val providers = Security.getProviders("SaslServerFactory.GSSAPI");
        if (providers == null || providers.length == 0) {
            throw new SaslException("No GSSAPI providers found in JVM security configuration");
        }

        return Arrays.stream(providers)
                .map(provider -> tryCreateFromProvider(provider, serverName, props, cbh))
                .filter(Objects::nonNull)
                .findFirst()
                .orElseThrow(() -> new SaslException(
                        "No native GSSAPI provider found (all providers excluding Hauthy were tried)"));
    }

    /**
     * Attempt to create a GSSAPI server from a single provider.
     *
     * @return SaslServer if successful, null if provider should be skipped or failed
     */
    private SaslServer tryCreateFromProvider(Provider provider,
                                             String serverName,
                                             Map<String, String> props,
                                             CallbackHandler cbh) {
        // Skip Hauthy's own provider to avoid infinite recursion
        // "Hauthy" == HauthySecurityProvider.PROVIDER_NAME — keep in sync if renamed
        if ("Hauthy".equalsIgnoreCase(provider.getName())) {
            log.debug("Skipping Hauthy provider for native GSSAPI creation to avoid recursion");
            return null;
        }

        val service = provider.getService("SaslServerFactory", MECHANISM_GSSAPI);
        if (service == null) {
            return null;
        }

        try {
            val factory = (SaslServerFactory) service.newInstance(null);
            val server = factory.createSaslServer(
                    MECHANISM_GSSAPI, "hbase", serverName, props, cbh);
            if (server != null) {
                log.debug("Created native GSSAPI server using provider: {}", provider.getName());
            }
            return server;
        } catch (Exception e) {
            log.debug("Provider {} failed to create GSSAPI server: {}",
                    provider.getName(), e.getMessage());
            return null;
        }
    }

    /**
     * Initialize Simple (no-auth) authentication.
     */
    private byte[] initSimpleAuth(byte[] response) {
        log.info("Initializing Simple auth for client {} (migration mode)", clientAddress);

        delegateSaslServer.set(new SimpleSaslServer(response, config));
        this.simpleMode = true;
        this.isComplete.set(true);
        this.authorizationId.set(extractSimpleUsername(response));

        metrics.recordSimpleSuccess();
        log.info("Simple auth successful for client {} as user '{}'",
                clientAddress, authorizationId.get());

        return new byte[0];
    }

    /**
     * Extract username from simple auth request, or use default.
     */
    private String extractSimpleUsername(byte[] response) {
        if (!config.isSimpleUserMapping()) {
            return config.getSimpleDefaultUser();
        }

        if (response != null && response.length > 0) {
            try {
                val responseStr = new String(response, StandardCharsets.UTF_8);
                val parts = responseStr.split("\0");
                if (parts.length > 0 && !parts[0].isEmpty()) {
                    return parts[0];
                }
            } catch (Exception e) {
                log.debug("Username extraction failed, using the default one and moving ahead");
            }
        }

        return config.getSimpleDefaultUser();
    }

    /**
     * Delegate response evaluation to the selected SASL server.
     */
    private byte[] delegateEvaluateResponse(byte[] response) throws SaslException {
        val delegate = delegateSaslServer.get();
        val challenge = delegate.evaluateResponse(response);

        if (delegate.isComplete()) {
            this.isComplete.set(true);
            this.authorizationId.set(delegate.getAuthorizationID());

            if (selectedAuthMode.get() == AuthMode.KERBEROS) {
                metrics.recordKerberosSuccess();
                log.info("Kerberos auth successful for client {} as '{}'",
                        clientAddress, authorizationId.get());
            }
        }

        return challenge;
    }

    /**
     * Get the server hostname for SASL negotiation.
     */
    private String getServerName() {
        if (serverPrincipal != null && serverPrincipal.contains("/")) {
            // Extract hostname from principal (e.g., "hbase/hostname@REALM" -> "hostname")
            val parts = serverPrincipal.split("/");
            if (parts.length > 1) {
                return parts[1].split("@")[0];
            }
        }
        try {
            return java.net.InetAddress.getLocalHost().getCanonicalHostName();
        } catch (Exception e) {
            log.warn("Could not determine local hostname", e);
            return "localhost";
        }
    }

    @Override
    public boolean isComplete() {
        return isComplete.get();
    }

    @Override
    public String getAuthorizationID() {
        return authorizationId.get();
    }

    @Override
    public String getMechanismName() {
        val mode = selectedAuthMode.get();
        if (mode == null) {
            return "DUAL-MODE";
        }
        return mode.getSaslMechanism();
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        val delegate = delegateSaslServer.get();
        if (delegate != null) {
            return delegate.getNegotiatedProperty(propName);
        }
        return null;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
        if (simpleMode) {
            // Simple mode - no wrapping
            val result = new byte[len];
            System.arraycopy(incoming, offset, result, 0, len);
            return result;
        }
        val delegate = delegateSaslServer.get();
        if (delegate != null) {
            return delegate.unwrap(incoming, offset, len);
        }
        throw new SaslException("SASL server not initialized");
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
        if (simpleMode) {
            // Simple mode - no wrapping
            val result = new byte[len];
            System.arraycopy(outgoing, offset, result, 0, len);
            return result;
        }
        val delegate = delegateSaslServer.get();
        if (delegate != null) {
            return delegate.wrap(outgoing, offset, len);
        }
        throw new SaslException("SASL server not initialized");
    }

    @Override
    public void dispose() throws SaslException {
        val delegate = delegateSaslServer.get();
        if (delegate != null) {
            delegate.dispose();
        }
        metrics.connectionClosed();
    }

    /**
     * Simple SASL server implementation for non-Kerberos clients.
     */
    private static class SimpleSaslServer implements SaslServer {

        private String authorizationId;

        SimpleSaslServer(byte[] initialResponse, HauthyConfig config) {
            if (initialResponse != null && initialResponse.length > 0 && config.isSimpleUserMapping()) {
                try {
                    val response = new String(initialResponse, StandardCharsets.UTF_8);
                    val parts = response.split("\0");
                    this.authorizationId = parts.length > 0 && !parts[0].isEmpty()
                            ? parts[0]
                            : config.getSimpleDefaultUser();
                } catch (Exception e) {
                    this.authorizationId = config.getSimpleDefaultUser();
                }
            } else {
                this.authorizationId = config.getSimpleDefaultUser();
            }
        }

        @Override
        public byte[] evaluateResponse(byte[] response) {
            return new byte[0]; // No challenge
        }

        @Override
        public boolean isComplete() {
            return true;
        }

        @Override
        public String getAuthorizationID() {
            return authorizationId;
        }

        @Override
        public String getMechanismName() {
            return AuthMode.SIMPLE.name();
        }

        @Override
        public Object getNegotiatedProperty(String propName) {
            if (Sasl.QOP.equals(propName)) {
                return "auth"; // Authentication only, no integrity/confidentiality
            }
            return null;
        }

        @Override
        public byte[] unwrap(byte[] incoming, int offset, int len) {
            val result = new byte[len];
            System.arraycopy(incoming, offset, result, 0, len);
            return result;
        }

        @Override
        public byte[] wrap(byte[] outgoing, int offset, int len) {
            val result = new byte[len];
            System.arraycopy(outgoing, offset, result, 0, len);
            return result;
        }

        @Override
        public void dispose() {
            // Nothing to dispose
        }
    }
}
