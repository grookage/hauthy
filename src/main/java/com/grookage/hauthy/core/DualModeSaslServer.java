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
package com.grookage.hauthy.core;

import com.grookage.hauthy.metrics.AuthMetrics;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.nio.charset.StandardCharsets;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;

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
    private SaslServer delegateSaslServer;
    @Getter
    private AuthMode selectedAuthMode;
    private String authorizationId;
    private boolean isComplete = false;
    @Getter
    private boolean simpleMode = false;
    // Connection info
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

    @Override
    public byte[] evaluateResponse(byte[] response) throws SaslException {
        try {
            if (delegateSaslServer == null) {
                // First message - determine auth mode
                return handleInitialResponse(response);
            } else {
                // Subsequent messages - delegate to selected SASL server
                return delegateEvaluateResponse(response);
            }
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
        final var requestedMode = detectAuthMode(response);
        log.debug("Client {} requesting auth mode: {}", clientAddress, requestedMode);

        // Validate the requested mode is allowed
        validateAuthMode(requestedMode);

        this.selectedAuthMode = requestedMode;

        // Create the appropriate SASL server
        return switch (requestedMode) {
            case KERBEROS -> initKerberosAuth(response);
            case SIMPLE, ANONYMOUS -> initSimpleAuth(response);
        };
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

        // Check for GSSAPI token (starts with specific ASN.1 header)
        // GSSAPI tokens start with 0x60 (APPLICATION 0 SEQUENCE)
        if ((response[0] & 0xFF) == 0x60) {
            return AuthMode.KERBEROS;
        }

        // Check for SASL mechanism name in the response
        try {
            final var responseStr = new String(response, StandardCharsets.UTF_8);
            if (responseStr.contains("GSSAPI")) {
                return AuthMode.KERBEROS;
            }
        } catch (Exception e) {
            // Ignore - might be binary data
        }

        return AuthMode.SIMPLE;
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

                // Check if this host is allowed for simple auth
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
     */
    private byte[] initKerberosAuth(byte[] response) throws SaslException {
        log.debug("Initializing Kerberos auth for client {}", clientAddress);

        try {
            if (serverSubject != null) {
                // Create GSSAPI SASL server under the server's Kerberos subject
                delegateSaslServer = Subject.doAs(serverSubject,
                        (PrivilegedExceptionAction<SaslServer>) () -> {
                            final var props = new HashMap<String, String>();
                            props.put(Sasl.QOP, "auth-conf,auth-int,auth");
                            props.put(Sasl.SERVER_AUTH, "true");

                            return Sasl.createSaslServer(
                                    MECHANISM_GSSAPI,
                                    "hbase",
                                    getServerName(),
                                    props,
                                    callbackHandler
                            );
                        });
            } else {
                // Fallback if no subject (shouldn't happen in production)
                log.warn("No server subject available for Kerberos auth");
                final var props = new HashMap<String, String>();
                props.put(Sasl.QOP, "auth");

                delegateSaslServer = Sasl.createSaslServer(
                        MECHANISM_GSSAPI,
                        "hbase",
                        getServerName(),
                        props,
                        callbackHandler
                );
            }

            this.simpleMode = false;

            // Process the initial token
            return delegateEvaluateResponse(response);

        } catch (PrivilegedActionException e) {
            metrics.recordKerberosFailure();
            final var cause = e.getCause();
            throw new SaslException("Failed to create Kerberos SASL server: " +
                    (cause != null ? cause.getMessage() : e.getMessage()), cause);
        }
    }

    /**
     * Initialize Simple (no-auth) authentication.
     */
    private byte[] initSimpleAuth(byte[] response) {
        log.info("Initializing Simple auth for client {} (migration mode)", clientAddress);

        // Create a simple "pass-through" SASL server
        delegateSaslServer = new SimpleSaslServer(response, config);
        this.simpleMode = true;

        // Simple auth completes immediately
        this.isComplete = true;
        this.authorizationId = extractSimpleUsername(response);

        metrics.recordSimpleSuccess();
        log.info("Simple auth successful for client {} as user '{}'",
                clientAddress, authorizationId);

        return null; // No challenge needed
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
                final var responseStr = new String(response, StandardCharsets.UTF_8);
                // Simple protocol: first token might be username
                final var parts = responseStr.split("\0");
                if (parts.length > 0 && !parts[0].isEmpty()) {
                    return parts[0];
                }
            } catch (Exception e) {
                // Ignore - use default
            }
        }

        return config.getSimpleDefaultUser();
    }

    /**
     * Delegate response evaluation to the selected SASL server.
     */
    private byte[] delegateEvaluateResponse(byte[] response) throws SaslException {
        final var challenge = delegateSaslServer.evaluateResponse(response);

        if (delegateSaslServer.isComplete()) {
            this.isComplete = true;
            this.authorizationId = delegateSaslServer.getAuthorizationID();

            if (selectedAuthMode == AuthMode.KERBEROS) {
                metrics.recordKerberosSuccess();
                log.info("Kerberos auth successful for client {} as '{}'",
                        clientAddress, authorizationId);
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
            final var parts = serverPrincipal.split("/");
            if (parts.length > 1) {
                final var hostRealm = parts[1];
                return hostRealm.split("@")[0];
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
        return isComplete;
    }

    @Override
    public String getAuthorizationID() {
        return authorizationId;
    }

    @Override
    public String getMechanismName() {
        if (selectedAuthMode == null) {
            return "DUAL-MODE";
        }
        return selectedAuthMode.getSaslMechanism();
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        if (delegateSaslServer != null) {
            return delegateSaslServer.getNegotiatedProperty(propName);
        }
        return null;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
        if (simpleMode) {
            // Simple mode - no wrapping
            final var result = new byte[len];
            System.arraycopy(incoming, offset, result, 0, len);
            return result;
        }
        if (delegateSaslServer != null) {
            return delegateSaslServer.unwrap(incoming, offset, len);
        }
        throw new SaslException("SASL server not initialized");
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
        if (simpleMode) {
            // Simple mode - no wrapping
            final var result = new byte[len];
            System.arraycopy(outgoing, offset, result, 0, len);
            return result;
        }
        if (delegateSaslServer != null) {
            return delegateSaslServer.wrap(outgoing, offset, len);
        }
        throw new SaslException("SASL server not initialized");
    }

    @Override
    public void dispose() throws SaslException {
        if (delegateSaslServer != null) {
            delegateSaslServer.dispose();
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
                    final var response = new String(initialResponse, StandardCharsets.UTF_8);
                    final var parts = response.split("\0");
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
            return null; // No challenge
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
            return "SIMPLE";
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
            final var result = new byte[len];
            System.arraycopy(incoming, offset, result, 0, len);
            return result;
        }

        @Override
        public byte[] wrap(byte[] outgoing, int offset, int len) {
            final var result = new byte[len];
            System.arraycopy(outgoing, offset, result, 0, len);
            return result;
        }

        @Override
        public void dispose() {
            // Nothing to dispose
        }
    }
}
