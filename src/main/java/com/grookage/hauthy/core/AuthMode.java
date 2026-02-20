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
        if (mechanism == null) {
            return SIMPLE;
        }
        return switch (mechanism.toUpperCase()) {
            case "GSSAPI" -> KERBEROS;
            case "SIMPLE", "PLAIN" -> SIMPLE;
            case "ANONYMOUS" -> ANONYMOUS;
            default -> SIMPLE;
        };
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
