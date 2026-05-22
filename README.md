# Hauthy - HBase Dual-Mode Authentication

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Java](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://openjdk.org/)
[![HBase](https://img.shields.io/badge/HBase-2.4%2B-green.svg)](https://hbase.apache.org/)

Hauthy (HBase AUTHentication hYbrid) enables **zero-downtime migration** from unauthenticated HBase clusters to Kerberos authentication by supporting both authentication modes simultaneously during the migration window.

---

## Table of Contents

- [Overview](#overview)
- [The Problem](#the-problem)
- [How Hauthy Solves It](#how-hauthy-solves-it)
- [Architecture](#architecture)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Migration Guide](#migration-guide)
- [Monitoring & Metrics](#monitoring--metrics)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

Hauthy is a Java security provider and HBase coprocessor that enables dual-mode authentication for Apache HBase clusters. It allows HBase to accept both **Simple (unauthenticated)** and **Kerberos (GSSAPI)** authentication simultaneously, making it possible to migrate production clusters to Kerberos without any downtime.

This is particularly valuable for:
- **Large-scale production clusters** with hundreds of client applications
- **Cross-datacenter replication** setups where both clusters need to remain operational
- **Organizations** that cannot afford maintenance windows for security migrations

---

## The Problem

Migrating an HBase cluster from Simple authentication to Kerberos authentication traditionally requires:

| Challenge | Impact |
|-----------|--------|
| **Complete cluster downtime** | All clients must be updated simultaneously |
| **Big-bang migration** | No gradual rollout possible; it's all-or-nothing |
| **Replication breaks** | Cross-cluster replication fails during migration |
| **Rollback difficulty** | If something goes wrong, rollback requires another downtime window |
| **Coordination overhead** | All client teams must coordinate changes for the same maintenance window |

For large-scale production clusters with hundreds of client applications and cross-datacenter replication, this approach is often **impractical or unacceptable**.

---

## How Hauthy Solves It

Hauthy introduces a **dual-mode authentication layer** that sits between HBase's RPC layer and the SASL authentication mechanism:

```
┌─────────────────────────────────────────────────────────────────┐
│                        HBase Cluster                            │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Hauthy Layer                           │  │
│  │  ┌─────────────────┐     ┌─────────────────────────────┐  │  │
│  │  │  Simple Auth    │     │     Kerberos Auth           │  │  │
│  │  │  (Legacy)       │     │     (Target)                │  │  │
│  │  └────────┬────────┘     └──────────────┬──────────────┘  │  │
│  │           │                             │                  │  │
│  │           └──────────┬──────────────────┘                  │  │
│  │                      │                                     │  │
│  │              ┌───────▼───────┐                             │  │
│  │              │ DualModeSasl  │                             │  │
│  │              │    Server     │                             │  │
│  │              └───────┬───────┘                             │  │
│  └──────────────────────┼────────────────────────────────────┘  │
│                         │                                       │
│                  ┌──────▼──────┐                                │
│                  │  HBase RPC  │                                │
│                  └─────────────┘                                │
└─────────────────────────────────────────────────────────────────┘
         ▲                                    ▲
         │                                    │
    ┌────┴────┐                          ┌────┴────┐
    │ Legacy  │                          │Kerberos │
    │ Client  │                          │ Client  │
    │(Simple) │                          │         │
    └─────────┘                          └─────────┘
```

### Key Benefits

| Benefit | Description |
|---------|-------------|
| **Zero Downtime** | Only rolling restarts required — no service interruption |
| **Gradual Migration** | Clients migrate at their own pace over days, weeks, or months |
| **Safe Rollback** | Simply disable Kerberos requirement if issues arise |
| **Replication Compatible** | Bi-directional replication works throughout the entire migration |
| **Observable** | JMX metrics track migration progress in real-time |

---

## Architecture

Hauthy consists of several components that work together seamlessly:

### Core Components

| Component | Description |
|-----------|-------------|
| `HauthySecurityProvider` | Java Security Provider that registers the dual-mode SASL mechanism with the JVM |
| `DualModeSaslServer` | Core SASL server implementation that intelligently handles both authentication modes |
| `DualModeSaslServerFactory` | Factory that creates `DualModeSaslServer` instances for each connection |
| `HauthyConfig` | Configuration holder loaded from HBase's `hbase-site.xml` |
| `HauthyInitializer` | Bootstrap class that initializes the security provider on startup |
| `HauthyCoprocessor` | HBase coprocessor that triggers initialization on Master and RegionServer startup |
| `AuthMetrics` | JMX metrics for monitoring authentication statistics and migration progress |

### Authentication Flow

The authentication flow works as follows:

1. **Client connects** to HBase RegionServer or Master
2. **SASL negotiation begins** — HBase initiates authentication handshake
3. **Hauthy intercepts** the SASL handshake via `DualModeSaslServerFactory`
4. **`DualModeSaslServer` analyzes** the initial client response:
   - If it contains a Kerberos token (GSSAPI) → delegate to standard GSSAPI handler
   - If it appears to be Simple auth → handle internally (if configuration allows)
5. **Authentication completes** with appropriate user principal established
6. **Metrics recorded** for monitoring and alerting

### Detection Logic

The `DualModeSaslServer` uses intelligent detection to determine the authentication type:

```
Initial Response Analysis:
├── Starts with GSSAPI token header (0x60)?
│   └── Yes → Kerberos authentication
├── Contains valid SIMPLE auth format?
│   └── Yes → Simple authentication (if allowed)
└── Unknown format → Reject with appropriate error
```

---

## Features

### Dual-Mode Authentication

Accept both Kerberos (GSSAPI) and Simple authentication connections simultaneously. The server automatically detects which authentication mechanism the client is using and handles it appropriately without any client-side changes required.

**How it works:**
- GSSAPI tokens are identified by their ASN.1 header structure
- Simple auth requests are identified by their plaintext format
- The detection happens transparently on the first message exchange

### Zero-Downtime Migration

Only rolling restarts are required to enable or disable Hauthy. There is no need to coordinate a maintenance window where all clients must be updated simultaneously.

**Migration timeline example:**
```
Day 1:  Deploy Hauthy, enable dual-mode (rolling restart)
Day 2:  Team A migrates their applications to Kerberos
Day 5:  Team B migrates their applications to Kerberos
Day 14: Team C migrates their batch jobs to Kerberos
Day 21: Verify 100% Kerberos, disable Simple auth (rolling restart)
```

### Seamless Replication

Cross-datacenter and bi-directional replication continues to work throughout the entire migration process. Both source and target clusters can be at different stages of migration.

**Supported scenarios:**
- Cluster A (dual-mode) ↔ Cluster B (simple-only)
- Cluster A (dual-mode) ↔ Cluster B (dual-mode)
- Cluster A (kerberos-only) ↔ Cluster B (dual-mode)

### Migration Metrics

Real-time JMX metrics expose authentication statistics including:
- Number of Kerberos vs Simple authentications
- Percentage of connections using Kerberos (migration progress indicator)
- Failed authentication attempts by type
- Active connection counts

**Example monitoring query:**
```bash
curl -s "http://regionserver:16030/jmx?qry=com.grookage.hauthy:*" | jq .
```

### Host-Based Restrictions

Optionally limit Simple authentication to specific hosts or IP ranges using wildcard patterns:

| Pattern | Matches |
|---------|---------|
| `10.0.1.100` | Exact IP address |
| `10.0.1.*` | IP range 10.0.1.0 - 10.0.1.255 |
| `10.0.*.*` | IP range 10.0.0.0 - 10.0.255.255 |
| `*.internal.example.com` | Hostname wildcard |
| `host1,host2,10.0.*.*` | Multiple patterns (comma-separated) |

This allows you to:
- Restrict Simple auth to internal networks only
- Gradually reduce the scope of Simple auth as migration progresses
- Block external access while still allowing internal legacy systems

### Graceful Degradation

If Hauthy encounters an error during initialization, it logs the error but does **not** prevent HBase from starting. This ensures a misconfiguration doesn't take down your production cluster.

**Behavior on error:**
```
Hauthy init error → Log error → Continue HBase startup → Use default auth
```

---

## Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| Java | 17 or higher | Required for `var` and modern language features |
| Apache HBase | 2.4.x or higher | Tested with 2.4.17 |
| Apache Hadoop | 3.3.x or higher | Tested with 3.3.4 |

**Important:** Hauthy must be built against the same major version of HBase and Hadoop that your cluster runs. The provided `pom.xml` is configured for HBase 2.4.17 and Hadoop 3.3.4. Adjust these versions in `pom.xml` to match your cluster before building.

---

## Installation

### Step 1: Build the JAR

```bash
cd scripts
./build.sh
```

This produces `target/hauthy-<version>.jar`.

### Step 2: Deploy to Cluster

Copy the JAR to the HBase classpath on **all Master and RegionServer nodes**:

```bash
# Option 1: Copy to HBase lib directory (recommended)
cp target/hauthy-*.jar /usr/lib/hbase/lib/

# Option 2: Use a custom directory and update HBASE_CLASSPATH
cp target/hauthy-*.jar /opt/hbase-extras/
echo 'export HBASE_CLASSPATH="/opt/hbase-extras/*:${HBASE_CLASSPATH}"' >> /etc/hbase/conf/hbase-env.sh
```

### Step 3: Configure HBase

Add Hauthy configuration to `hbase-site.xml` on all nodes. See the [Configuration](#configuration) section for details.

### Step 4: Rolling Restart

Perform a rolling restart of your HBase cluster to activate Hauthy:

```bash
# Restart RegionServers one at a time
for rs in $(cat regionservers.txt); do
    ssh $rs "sudo systemctl restart hbase-regionserver"
    sleep 60  # Wait for regions to rebalance
done

# Restart Masters
sudo systemctl restart hbase-master
```

---

## Configuration

### Basic Configuration

Add the following to `hbase-site.xml` on all nodes:

```xml
<!-- Enable Hauthy dual-mode authentication -->
<property>
    <name>hauthy.enabled</name>
    <value>true</value>
    <description>Enable dual-mode authentication support</description>
</property>

<!-- Allow both authentication modes during migration -->
<property>
    <name>hauthy.allow.simple</name>
    <value>true</value>
    <description>Allow unauthenticated Simple connections</description>
</property>

<property>
    <name>hauthy.allow.kerberos</name>
    <value>true</value>
    <description>Allow Kerberos GSSAPI connections</description>
</property>

<!-- Load Hauthy coprocessor on Master -->
<property>
    <name>hbase.coprocessor.master.classes</name>
    <value>com.grookage.hauthy.coprocessor.HauthyCoprocessor</value>
</property>

<!-- Load Hauthy coprocessor on RegionServers -->
<property>
    <name>hbase.coprocessor.regionserver.classes</name>
    <value>com.grookage.hauthy.coprocessor.HauthyCoprocessor</value>
</property>
```

### Configuration Reference

| Property | Default | Description |
|----------|---------|-------------|
| `hauthy.enabled` | `false` | Master switch to enable dual-mode authentication. When `false`, Hauthy is completely disabled and HBase uses its default authentication. |
| `hauthy.allow.simple` | `true` | Allow Simple (unauthenticated) connections. Set to `false` to disable Simple auth and require Kerberos for all connections. |
| `hauthy.allow.kerberos` | `true` | Allow Kerberos (GSSAPI) connections. Should almost always be `true`. |
| `hauthy.simple.allowed.hosts` | `*` (all) | Comma-separated list of hosts/IPs allowed to use Simple auth. Supports wildcards: `10.0.1.*`, `192.168.*.*`, `internal-*.example.com`. Empty or `*` means all hosts are allowed. |
| `hauthy.simple.default.user` | `hbase` | Default username assigned to Simple auth connections when no username can be extracted from the request. |
| `hauthy.simple.user.mapping` | `true` | Attempt to extract the actual username from Simple auth requests. When `false`, all Simple auth users are assigned `simple.default.user`. |
| `hauthy.metrics.enabled` | `true` | Enable JMX metrics for authentication monitoring. Disable only if you have concerns about JMX overhead. |
| `hauthy.metrics.jmx.domain` | `com.grookage.hauthy` | JMX domain for metrics MBean registration. Change if you need to avoid naming conflicts. |

### Example Configurations

**Dual-Mode (Migration Phase)** — See `conf/hbase-site.xml.dual-mode`

```xml
<property>
    <name>hauthy.enabled</name>
    <value>true</value>
</property>
<property>
    <name>hauthy.allow.simple</name>
    <value>true</value>
</property>
<property>
    <name>hauthy.allow.kerberos</name>
    <value>true</value>
</property>
<!-- Optional: Restrict simple auth to internal networks -->
<property>
    <name>hauthy.simple.allowed.hosts</name>
    <value>10.0.*.*,192.168.*.*</value>
</property>
```

**Kerberos-Only (Post-Migration)** — See `conf/hbase-site.xml.kerberos-only`

```xml
<property>
    <name>hauthy.enabled</name>
    <value>true</value>
</property>
<property>
    <name>hauthy.allow.simple</name>
    <value>false</value>
</property>
<property>
    <name>hauthy.allow.kerberos</name>
    <value>true</value>
</property>
```

---

## Migration Guide

### Phase 1: Preparation (1-2 weeks before migration)

**Prerequisites checklist:**

- [ ] KDC (Key Distribution Center) infrastructure is set up and operational
- [ ] Service principals created for all HBase Masters and RegionServers
- [ ] Keytab files generated and securely distributed to all nodes
- [ ] HBase configured for Kerberos authentication (standard HBase Kerberos setup)
- [ ] Hauthy built and tested thoroughly in a staging environment
- [ ] Monitoring and alerting configured for Hauthy JMX metrics
- [ ] Runbook prepared for common issues and rollback procedures

**Validation steps:**

```bash
# Verify Kerberos is working on each HBase node
kinit -kt /etc/security/keytabs/hbase.service.keytab hbase/hostname@REALM
klist

# Verify keytab permissions
ls -la /etc/security/keytabs/hbase.service.keytab
# Should be: -r-------- 1 hbase hbase
```

### Phase 2: Enable Dual-Mode (Day 1)

1. **Deploy Hauthy JAR** to all Masters and RegionServers (see [Installation](#installation))

2. **Update `hbase-site.xml`** with Hauthy configuration (dual-mode enabled)

3. **Rolling restart** the cluster — one node at a time

4. **Verify both auth modes work:**
   ```bash
   # Test Simple auth (should still work)
   hbase shell -n <<< "status 'simple'"
   
   # Test Kerberos auth (should now work)
   kinit user@REALM
   hbase shell -n <<< "status 'detailed'"
   ```

5. **Check Hauthy metrics are available:**
   ```bash
   curl -s "http://<regionserver>:16030/jmx?qry=com.grookage.hauthy:*"
   ```

### Phase 3: Migrate Clients (Days 2 - N)

This is typically the longest phase. The duration depends on the number of client applications and team coordination.

**Activities during this phase:**

1. **Notify client teams** that Kerberos migration is now possible
2. **Provide migration documentation** for each client type (see examples below)
3. **Monitor migration progress** via JMX metrics (`KerberosPercentage`)
4. **Set incremental milestones** (e.g., 25%, 50%, 75%, 100%)
5. **Address issues** as teams report them

**Client Migration Example — Java HBase Client:**

```java
// BEFORE (Simple auth)
Configuration conf = HBaseConfiguration.create();
Connection conn = ConnectionFactory.createConnection(conf);

// AFTER (Kerberos auth)
Configuration conf = HBaseConfiguration.create();
conf.set("hbase.security.authentication", "kerberos");
conf.set("hbase.master.kerberos.principal", "hbase/_HOST@REALM");
conf.set("hbase.regionserver.kerberos.principal", "hbase/_HOST@REALM");

// Login with keytab before creating connection
UserGroupInformation.setConfiguration(conf);
UserGroupInformation.loginUserFromKeytab("client@REALM", "/path/to/client.keytab");

Connection conn = ConnectionFactory.createConnection(conf);
```

**Client Migration Example — Spark with HBase:**

```scala
// Add to Spark configuration
spark.hadoop.hbase.security.authentication=kerberos
spark.hadoop.hbase.master.kerberos.principal=hbase/_HOST@REALM
spark.hadoop.hbase.regionserver.kerberos.principal=hbase/_HOST@REALM

// Ensure keytab is distributed to executors
spark.yarn.keytab=/path/to/client.keytab
spark.yarn.principal=client@REALM
```

### Phase 4: Tighten Restrictions (Optional)

As migration progresses, you can incrementally tighten host restrictions to encourage migration:

```xml
<!-- Week 1: Allow simple from all internal hosts -->
<property>
    <name>hauthy.simple.allowed.hosts</name>
    <value>10.*.*.*,192.168.*.*</value>
</property>

<!-- Week 2: Restrict to specific subnets -->
<property>
    <name>hauthy.simple.allowed.hosts</name>
    <value>10.0.1.*,10.0.2.*</value>
</property>

<!-- Week 3: Only specific legacy hosts that haven't migrated yet -->
<property>
    <name>hauthy.simple.allowed.hosts</name>
    <value>10.0.1.100,10.0.1.101,10.0.1.102</value>
</property>
```

Each change requires a rolling restart to take effect.

### Phase 5: Disable Simple Auth (Final)

Once the `KerberosPercentage` metric reaches **100%** and all clients are confirmed migrated:

1. **Update configuration:**
   ```xml
   <property>
       <name>hauthy.allow.simple</name>
       <value>false</value>
   </property>
   ```

2. **Rolling restart** the cluster

3. **Verify all connections are Kerberos:**
   ```bash
   # Check metrics - SimpleAuthSuccess should stop incrementing
   curl -s "http://regionserver:16030/jmx?qry=com.grookage.hauthy:*" | \
     jq '.beans[0] | {SimpleAuthSuccess, KerberosAuthSuccess, KerberosPercentage}'
   ```

4. **Monitor for SimpleAuthRejected** — these indicate clients that weren't fully migrated

5. **(Optional) Remove Hauthy** if no longer needed, or keep it for:
   - Continued metrics collection
   - Easy rollback capability if issues discovered later
   - Additional logging and observability

---

## Monitoring & Metrics

### JMX Metrics

Hauthy exposes comprehensive metrics via JMX under the MBean:

```
com.grookage.hauthy:type=AuthMetrics
```

**Access methods:**

```bash
# Via HTTP (RegionServer web UI)
curl "http://<regionserver>:16030/jmx?qry=com.grookage.hauthy:*"

# Via HTTP (Master web UI)
curl "http://<master>:16010/jmx?qry=com.grookage.hauthy:*"

# Via JConsole/VisualVM
# Connect to HBase JMX port and navigate to com.grookage.hauthy domain
```

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `KerberosAuthSuccess` | Counter | Total successful Kerberos authentications since process startup |
| `KerberosAuthFailure` | Counter | Total failed Kerberos authentication attempts (bad credentials, expired tickets, etc.) |
| `SimpleAuthSuccess` | Counter | Total successful Simple authentications |
| `SimpleAuthRejected` | Counter | Simple auth attempts rejected due to host restrictions or Simple auth being disabled |
| `TotalConnections` | Counter | Total authentication attempts processed (success + failure) |
| `ActiveConnections` | Gauge | Currently active authenticated connections |
| `KerberosPercentage` | Gauge | Percentage of successful authentications using Kerberos — **this is your migration progress indicator** |

### Alerting Recommendations

Configure alerts for the following scenarios:

| Condition | Alert Level | Meaning |
|-----------|-------------|---------|
| `KerberosAuthFailure` increasing rapidly | Warning | May indicate misconfigured clients, expired keytabs, or KDC issues |
| `SimpleAuthRejected` spike | Warning | Unauthorized access attempts or clients trying from non-allowed hosts |
| `KerberosPercentage` regression | Warning | New clients deploying with Simple auth instead of Kerberos |
| `KerberosPercentage` stuck below target | Info | Migration stalled; follow up with remaining teams |

### Prometheus/Grafana Integration

If you use Prometheus with JMX Exporter, add Hauthy metrics to your scrape configuration:

```yaml
# prometheus-jmx-config.yaml
rules:
  - pattern: 'com.grookage.hauthy<type=AuthMetrics><>(\w+)'
    name: hauthy_$1
    type: GAUGE
```

**Example Grafana queries:**

```promql
# Migration progress across all RegionServers
avg(hauthy_KerberosPercentage{job="hbase-regionserver"})

# Authentication rate by type
rate(hauthy_KerberosAuthSuccess{instance=~".*"}[5m])
rate(hauthy_SimpleAuthSuccess{instance=~".*"}[5m])

# Failed authentication rate
rate(hauthy_KerberosAuthFailure[5m])
rate(hauthy_SimpleAuthRejected[5m])
```

---

## Security Considerations

### During Migration Window

⚠️ **Important:** During the dual-mode migration window, security is relaxed. Be aware of these risks:

| Risk | Mitigation |
|------|------------|
| **Simple auth is inherently insecure** — anyone who can reach HBase ports can authenticate | Use network segmentation; ensure HBase ports are not exposed to untrusted networks |
| **Credential stuffing** — attackers may try common usernames | Monitor `SimpleAuthSuccess` for unexpected patterns |
| **Lateral movement** — compromised internal host can access HBase | Use `hauthy.simple.allowed.hosts` to limit exposure |
| **Extended exposure** — longer migration = longer risk window | Set clear deadlines; minimize migration duration |

### Host Restriction Best Practices

Use `hauthy.simple.allowed.hosts` strategically:

```xml
<!-- Good: Specific internal subnets only -->
<property>
    <name>hauthy.simple.allowed.hosts</name>
    <value>10.0.1.*,10.0.2.*</value>
</property>

<!-- Better: Only specific application servers -->
<property>
    <name>hauthy.simple.allowed.hosts</name>
    <value>app-server-01.internal,app-server-02.internal</value>
</property>

<!-- Bad: Allow everything (default) -->
<property>
    <name>hauthy.simple.allowed.hosts</name>
    <value>*</value>
</property>
```

### Post-Migration Security

After completing migration:

1. **Disable Simple auth immediately** — don't leave it enabled "just in case"
2. **Audit access logs** — review any unusual Simple auth attempts during migration
3. **Keep Hauthy with `allow.simple=false`** — provides additional logging and easy rollback
4. **Update firewall rules** — if you opened any ports for migration, close them

---

## Troubleshooting

### Hauthy Not Initializing

**Symptom:** No Hauthy log messages on HBase startup; metrics endpoint returns empty

**Diagnostic steps:**

```bash
# 1. Verify JAR is in classpath
ls -la /usr/lib/hbase/lib/hauthy*.jar

# 2. Check coprocessor is configured
grep -i hauthy /etc/hbase/conf/hbase-site.xml

# 3. Search for errors in HBase logs
grep -i hauthy /var/log/hbase/hbase-*.log
grep -i "coprocessor" /var/log/hbase/hbase-*.log | grep -i error

# 4. Verify hauthy.enabled is true
grep "hauthy.enabled" /etc/hbase/conf/hbase-site.xml
```

**Common causes:**
- JAR not deployed to all nodes
- Typo in coprocessor class name
- `hauthy.enabled` set to `false`

### Kerberos Authentication Failing

**Symptom:** `KerberosAuthFailure` metric increasing; Kerberos clients cannot connect

**Diagnostic steps:**

```bash
# 1. Test keytab manually on the HBase node
kinit -kt /etc/security/keytabs/hbase.service.keytab hbase/$(hostname -f)@REALM
klist

# 2. Check clock synchronization (Kerberos requires <5 min skew)
ntpq -p
date

# 3. Verify principal names in configuration match keytab
klist -kt /etc/security/keytabs/hbase.service.keytab
grep "kerberos.principal" /etc/hbase/conf/hbase-site.xml

# 4. Check KDC is reachable
kinit testuser@REALM  # Interactive test
```

**Common causes:**
- Clock skew > 5 minutes
- Keytab file permissions incorrect (should be 0400, owned by hbase)
- Principal name mismatch between config and keytab
- KDC unreachable or overloaded

### Simple Auth Rejected Unexpectedly

**Symptom:** `SimpleAuthRejected` increasing; legacy clients cannot connect

**Diagnostic steps:**

```bash
# 1. Check if Simple auth is enabled
grep "hauthy.allow.simple" /etc/hbase/conf/hbase-site.xml

# 2. Check allowed hosts configuration
grep "hauthy.simple.allowed.hosts" /etc/hbase/conf/hbase-site.xml

# 3. Verify client IP is in allowed list
# (Check client IP and compare against allowed patterns)

# 4. Check HBase logs for rejection messages
grep -i "simple.*reject" /var/log/hbase/hbase-*.log
```

**Common causes:**
- `hauthy.allow.simple` set to `false`
- Client IP not in `hauthy.simple.allowed.hosts` pattern
- Typo in host pattern (e.g., `10.0.1*` instead of `10.0.1.*`)

### Metrics Not Available

**Symptom:** JMX endpoint returns no Hauthy metrics; monitoring shows gaps

**Diagnostic steps:**

```bash
# 1. Check if metrics are enabled
grep "hauthy.metrics.enabled" /etc/hbase/conf/hbase-site.xml

# 2. Verify Hauthy initialized (check logs)
grep "HauthyCoprocessor started" /var/log/hbase/hbase-*.log

# 3. Test JMX endpoint directly
curl -v "http://localhost:16030/jmx?qry=com.grookage.hauthy:*"

# 4. Check for JMX registration errors
grep -i "jmx" /var/log/hbase/hbase-*.log | grep -i error
```

**Common causes:**
- `hauthy.metrics.enabled` set to `false`
- JMX port not exposed or firewalled
- MBean name conflict with existing registration

---

## Contributing

Contributions are welcome! Please follow these guidelines:

### Getting Started

1. **Fork** the repository
2. **Clone** your fork locally
3. **Create a feature branch**: `git checkout -b feature/my-feature`
4. **Make your changes** with tests
5. **Run tests** to ensure everything passes
6. **Submit a pull request** with a clear description

### Code Style Guidelines

- Follow standard Java conventions
- Use `final var` for local variables where applicable
- Use Lombok annotations (`@Slf4j`, `@Getter`, etc.) to reduce boilerplate
- Add Javadoc for all public classes and methods
- Keep methods focused and under 30 lines where possible
- Write unit tests for all new functionality

### Commit Message Format

```
type(scope): description

[optional body]

[optional footer]
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

**Example:**
```
feat(metrics): add connection duration histogram

Adds a new metric to track the duration of authenticated connections,
useful for identifying long-running connections during migration.

Closes #42
```

---

## License

```
Copyright 2026 Koushik R <rkoushik.14@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

**Questions or issues?** Open an issue on GitHub or reach out to the maintainers.
