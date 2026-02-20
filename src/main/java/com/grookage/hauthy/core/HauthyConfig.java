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

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import org.apache.hadoop.conf.Configuration;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Configuration for Hauthy dual-mode authentication.
 *
 * <p>This class holds all configuration parameters for dual-mode authentication,
 * loaded from HBase configuration or constructed programmatically.</p>
 *
 * <h3>Configuration Properties:</h3>
 * <ul>
 *   <li>{@code hauthy.enabled} - Enable dual-mode authentication</li>
 *   <li>{@code hauthy.allow.simple} - Allow simple (unauthenticated) connections</li>
 *   <li>{@code hauthy.allow.kerberos} - Allow Kerberos connections</li>
 *   <li>{@code hauthy.simple.allowed.hosts} - Hosts allowed to use simple auth</li>
 *   <li>{@code hauthy.simple.default.user} - Default user for simple auth</li>
 * </ul>
 */
@Getter
@Builder
@ToString
public class HauthyConfig {

    // Configuration keys
    public static final String HAUTHY_ENABLED = "hauthy.enabled";
    public static final String ALLOW_SIMPLE = "hauthy.allow.simple";
    public static final String ALLOW_KERBEROS = "hauthy.allow.kerberos";
    public static final String SIMPLE_ALLOWED_HOSTS = "hauthy.simple.allowed.hosts";
    public static final String SIMPLE_DEFAULT_USER = "hauthy.simple.default.user";
    public static final String SIMPLE_USER_MAPPING = "hauthy.simple.user.mapping";
    public static final String METRICS_ENABLED = "hauthy.metrics.enabled";
    public static final String METRICS_JMX_DOMAIN = "hauthy.metrics.jmx.domain";

    // Defaults
    private static final boolean DEFAULT_ENABLED = false;
    private static final boolean DEFAULT_ALLOW_SIMPLE = true;
    private static final boolean DEFAULT_ALLOW_KERBEROS = true;
    private static final String DEFAULT_SIMPLE_USER = "hbase";
    private static final boolean DEFAULT_USER_MAPPING = true;
    private static final boolean DEFAULT_METRICS_ENABLED = true;
    private static final String DEFAULT_JMX_DOMAIN = "com.grookage.hauthy";

    /**
     * Whether dual-mode authentication is enabled.
     */
    @Builder.Default
    private final boolean enabled = DEFAULT_ENABLED;

    /**
     * Whether simple (unauthenticated) connections are allowed.
     */
    @Builder.Default
    private final boolean allowSimple = DEFAULT_ALLOW_SIMPLE;

    /**
     * Whether Kerberos authenticated connections are allowed.
     */
    @Builder.Default
    private final boolean allowKerberos = DEFAULT_ALLOW_KERBEROS;

    /**
     * Set of hosts/IPs allowed to use simple authentication.
     * Empty set means all hosts are allowed.
     */
    @Builder.Default
    private final Set<String> simpleAllowedHosts = Collections.emptySet();

    /**
     * Default username for simple auth connections.
     */
    @Builder.Default
    private final String simpleDefaultUser = DEFAULT_SIMPLE_USER;

    /**
     * Whether to attempt to extract username from simple auth requests.
     */
    @Builder.Default
    private final boolean simpleUserMapping = DEFAULT_USER_MAPPING;

    /**
     * Whether metrics collection is enabled.
     */
    @Builder.Default
    private final boolean metricsEnabled = DEFAULT_METRICS_ENABLED;

    /**
     * JMX domain for metrics.
     */
    @Builder.Default
    private final String metricsJmxDomain = DEFAULT_JMX_DOMAIN;

    /**
     * Load configuration from Hadoop Configuration.
     *
     * @param conf Hadoop configuration
     * @return HauthyConfig instance
     */
    public static HauthyConfig fromConfiguration(Configuration conf) {
        if (conf == null) {
            return HauthyConfig.builder().build();
        }

        // Parse allowed hosts
        var allowedHosts = Collections.<String>emptySet();
        final var hostsStr = conf.get(SIMPLE_ALLOWED_HOSTS, "*");
        if (!"*".equals(hostsStr) && !hostsStr.isEmpty()) {
            allowedHosts = new HashSet<>(Arrays.asList(hostsStr.split(",")));
        }

        return HauthyConfig.builder()
                .enabled(conf.getBoolean(HAUTHY_ENABLED, DEFAULT_ENABLED))
                .allowSimple(conf.getBoolean(ALLOW_SIMPLE, DEFAULT_ALLOW_SIMPLE))
                .allowKerberos(conf.getBoolean(ALLOW_KERBEROS, DEFAULT_ALLOW_KERBEROS))
                .simpleAllowedHosts(allowedHosts)
                .simpleDefaultUser(conf.get(SIMPLE_DEFAULT_USER, DEFAULT_SIMPLE_USER))
                .simpleUserMapping(conf.getBoolean(SIMPLE_USER_MAPPING, DEFAULT_USER_MAPPING))
                .metricsEnabled(conf.getBoolean(METRICS_ENABLED, DEFAULT_METRICS_ENABLED))
                .metricsJmxDomain(conf.get(METRICS_JMX_DOMAIN, DEFAULT_JMX_DOMAIN))
                .build();
    }

    /**
     * Check if the given host is allowed to use simple authentication.
     *
     * @param host client host address
     * @return true if simple auth is allowed for this host
     */
    public boolean isSimpleAuthAllowedForHost(String host) {
        if (!allowSimple) {
            return false;
        }

        // Empty set means all hosts allowed
        if (simpleAllowedHosts.isEmpty()) {
            return true;
        }

        if (host == null) {
            return false;
        }

        // Check exact match or pattern match
        for (String allowed : simpleAllowedHosts) {
            if (allowed.equals(host)) {
                return true;
            }
            // Simple wildcard matching (e.g., "10.0.1.*")
            if (allowed.endsWith("*")) {
                String prefix = allowed.substring(0, allowed.length() - 1);
                if (host.startsWith(prefix)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Validate the configuration.
     *
     * @throws IllegalStateException if configuration is invalid
     */
    public void validate() {
        if (enabled && !allowSimple && !allowKerberos) {
            throw new IllegalStateException(
                    "At least one auth mode must be allowed when hauthy is enabled");
        }
    }
}
