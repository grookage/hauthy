package com.grookage.hauthy.core;

import lombok.Getter;

/**
 * Authentication modes supported by the dual-mode SASL server.
 *
 * <p>During migration, both KERBEROS and SIMPLE modes can be enabled,
 * allowing gradual client migration without service disruption.</p>
 */
@Getter
public enum AuthMode {

    /**
     * Kerberos authentication using GSSAPI SASL mechanism.
     * This is the target state after migration.
     */
    KERBEROS("GSSAPI", true),

    /**
     * Simple authentication - no real authentication performed.
     * Used for legacy clients during migration window.
     */
    SIMPLE("SIMPLE", false),

    /**
     * Anonymous authentication - accepts any connection.
     * Maps to a default user identity.
     */
    ANONYMOUS("ANONYMOUS", false);

    private final String saslMechanism;
    private final boolean secure;

    AuthMode(String saslMechanism, boolean secure) {
        this.saslMechanism = saslMechanism;
        this.secure = secure;
    }

    /**
     * Parse auth mode from SASL mechanism name.
     *
     * @param mechanism SASL mechanism name (e.g., "GSSAPI", "PLAIN")
     * @return corresponding AuthMode, defaults to SIMPLE if unknown
     */
    public static AuthMode fromMechanism(String mechanism) {
        if (null == mechanism) {
            return SIMPLE;
        }
        switch (mechanism.toUpperCase()) {
            case "GSSAPI":
                return KERBEROS;
            case "ANONYMOUS":
                return ANONYMOUS;
            default:
                return SIMPLE;
        }
    }

    /**
     * Check if this mode requires Kerberos infrastructure.
     *
     * @return true if Kerberos is required
     */
    public boolean requiresKerberos() {
        return this == KERBEROS;
    }
}
