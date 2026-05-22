# Hauthy - HBase Dual-Mode SASL Client

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Java](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://openjdk.org/)
[![HBase](https://img.shields.io/badge/HBase-2.4%2B-green.svg)](https://hbase.apache.org/)

Hauthy enables **zero-downtime bidirectional replication** between kerberized and non-kerberized HBase clusters. Its core component, `DualModeSaslClient`, intercepts SASL authentication failures (e.g., KDC error 7 when a kerberized client connects to a non-kerberized ZooKeeper) and gracefully falls back to unauthenticated mode instead of failing the connection.

---

## The Problem

Cross-cluster HBase replication between a kerberized cluster and a non-kerberized cluster fails at the ZooKeeper layer -- before HBase RPC is even involved:

```
Kerberized RS --ZK--> Non-Kerb ZK
   GSSAPI attempted -> KDC error 7 (principal not found) -> CONNECTION FAILS
```

The kerberized client's JAAS config forces a GSSAPI handshake against the remote ZK, but the remote ZK's principal doesn't exist in the source KDC. Standard ZK client has no fallback -- it just dies.

---

## How Hauthy Solves It

`DualModeSaslClient` is a custom SASL client registered via Java's Security Provider SPI. When the KDC rejects the remote principal (error 7), instead of propagating the failure, it sends an empty token -- signaling to ZooKeeper that SASL auth should be abandoned. Combined with `allowSaslFailedClients=true` on the remote ZK, the connection succeeds as unauthenticated.

```
Kerberized RS --ZK--> Non-Kerb ZK
   GSSAPI attempted -> KDC error 7
   DualModeSaslClient catches error -> sends empty token
   ZK (allowSaslFailedClients=true) -> accepts session
   Connection established
```

---

## Components

| Component | Role |
|-----------|------|
| `DualModeSaslClient` | SASL client that intercepts KDC failures and falls back to no-op auth |
| `DualModeSaslClientFactory` | SaslClientFactory that creates `DualModeSaslClient` instances |
| `DualModeSaslServer` | SASL server that accepts both Simple and Kerberos connections (for intra-cluster migration) |
| `DualModeSaslServerFactory` | Factory for `DualModeSaslServer` |
| `HauthySecurityProvider` | Java Security Provider that registers all SASL factories with the JVM |
| `HauthyCoprocessor` | HBase coprocessor that bootstraps Hauthy on Master/RegionServer startup |
| `HauthyConfig` | Configuration loaded from `hbase-site.xml` |
| `AuthMetrics` | JMX metrics for monitoring auth patterns |

---

## Migration: Cross-Cluster Replication (Secure <> Unsecure)

Bidirectional HBase replication between a **kerberized cluster (Site1)** and a **non-kerberized cluster (Site2)**.

| Cluster | Auth     | Role                   |
|---------|----------|------------------------|
| Site1   | Kerberos | Kerberized cluster     |
| Site2   | Simple   | Non-kerberized cluster |

### What Breaks Without Hauthy

| Direction             | Layer | Problem                                                                              |
|-----------------------|-------|--------------------------------------------------------------------------------------|
| Site1 (Kerb) to Site2 | ZK    | Site1 ZK client attempts GSSAPI to Site2 ZK; principal not in KDC (error 7)          |
| Site1 (Kerb) to Site2 | RPC   | Site1 RS sends `KERBEROS`; Site2 downgrades to simple; Site1 rejects the downgrade   |
| Site2 (Simple) to Site1 | ZK  | Works natively (no JAAS config, no SASL attempted)                                   |
| Site2 (Simple) to Site1 | RPC | Site2 sends `SIMPLE`; Site1 rejects: "Authentication is required"                    |

### Solution

| Direction             | Layer | Fix                                                              | Where            |
|-----------------------|-------|------------------------------------------------------------------|------------------|
| Site1 (Kerb) to Site2 | ZK    | Hauthy `DualModeSaslClient` + `allowSaslFailedClients=true`     | Site1 + Site2 ZK |
| Site1 (Kerb) to Site2 | RPC   | `hbase.ipc.client.fallback-to-simple-auth-allowed=true`          | Site1            |
| Site2 (Simple) to Site1 | ZK  | No fix needed                                                    | --               |
| Site2 (Simple) to Site1 | RPC | `hbase.ipc.server.fallback-to-simple-auth-allowed=true`          | Site1            |

### Configuration

**Site1 (Kerberized) -- hbase-site.xml:**

```xml
<property><name>hauthy.enabled</name><value>true</value></property>

<!-- DualModeSaslClient: graceful no-op ZK SASL when connecting to Site2 ZK -->
<property><name>hauthy.zk.sasl.fallback</name><value>true</value></property>

<!-- Accept simple auth RPC from Site2 -->
<property><name>hbase.ipc.server.fallback-to-simple-auth-allowed</name><value>true</value></property>

<!-- Allow Site1 RPC client to fall back when Site2 downgrades -->
<property><name>hbase.ipc.client.fallback-to-simple-auth-allowed</name><value>true</value></property>

<property><name>hbase.coprocessor.master.classes</name><value>com.grookage.hauthy.coprocessor.HauthyCoprocessor</value></property>
<property><name>hbase.coprocessor.regionserver.classes</name><value>com.grookage.hauthy.coprocessor.HauthyCoprocessor</value></property>
```

**Site2 (Non-Kerberized) -- zoo.cfg:**

```properties
# Accept failed SASL sessions (DualModeSaslClient sends empty token)
allowSaslFailedClients=true
```

No HBase changes needed on Site2.

### Deployment

1. **Deploy Hauthy JAR on Site1** (all Masters + RegionServers)
2. **Add hbase-site.xml properties on Site1**
3. **Add `allowSaslFailedClients=true` to Site2 zoo.cfg**
4. **Rolling restart Site2 ZooKeeper** (followers first, leader last)
5. **Rolling restart Site1 HBase** (RegionServers first, then Masters)
6. **Add replication peers:**
   ```bash
   # On Site2:
   add_peer 'SITE1', CLUSTER_KEY => 'site1-zk1:2181,site1-zk2:2181,site1-zk3:2181:/hbase'

   # On Site1 (after kinit):
   add_peer 'SITE2', CLUSTER_KEY => 'site2-zk1:2181,site2-zk2:2181,site2-zk3:2181:/hbase', \
     CONFIG => {'hbase.security.authentication' => 'simple', 'hbase.ipc.client.fallback-to-simple-auth-allowed' => 'true'}
   ```

### How It Works (Detail)

**Site1 (Kerb) replicating to Site2 (Simple):**
```
Site1 RS --ZK--> Site2 ZK
  |  GSSAPI attempted -> KDC error 7 (principal not found)
  |  DualModeSaslClient catches error 7 -> sends empty token
  |  Site2 ZK (allowSaslFailedClients=true) -> accepts session
  |
  +--RPC--> Site2 RS
     Site1 sends auth_method=KERBEROS
     Site2 (non-secure) downgrades -> "use simple"
     Site1 (client.fallback-to-simple=true) -> accepts downgrade
     WALs shipped successfully
```

**Site2 (Simple) replicating to Site1 (Kerb):**
```
Site2 RS --ZK--> Site1 ZK
  |  No JAAS config -> no SASL attempted -> plain connection
  |  Site1 ZK accepts unauthenticated session
  |
  +--RPC--> Site1 RS
     Site2 sends auth_method=SIMPLE
     Site1 (server.fallback-to-simple=true) -> allows simple client
     WALs shipped successfully
```

---

## Migration: Unsecure to Secure (Intra-Cluster)

For migrating a single cluster's clients from Simple to Kerberos without downtime, `DualModeSaslServer` accepts both auth modes simultaneously on the server side.

### Steps

1. **Deploy Hauthy** with dual-mode config:
   ```xml
   <property><name>hauthy.enabled</name><value>true</value></property>
   <property><name>hauthy.allow.simple</name><value>true</value></property>
   <property><name>hauthy.allow.kerberos</name><value>true</value></property>
   <property><name>hbase.coprocessor.master.classes</name><value>com.grookage.hauthy.coprocessor.HauthyCoprocessor</value></property>
   <property><name>hbase.coprocessor.regionserver.classes</name><value>com.grookage.hauthy.coprocessor.HauthyCoprocessor</value></property>
   ```
2. **Rolling restart** HBase
3. **Migrate clients** at their own pace (`hbase.security.authentication=kerberos` + keytab)
4. **Monitor** via JMX: watch `KerberosPercentage` reach 100%
5. **Lock down**: set `hauthy.allow.simple=false`, rolling restart

---

## Configuration Reference

| Property | Default | Description |
|----------|---------|-------------|
| `hauthy.enabled` | `false` | Master switch for Hauthy |
| `hauthy.zk.sasl.fallback` | `false` | Enable DualModeSaslClient ZK fallback for cross-cluster replication |
| `hauthy.allow.simple` | `true` | Allow Simple connections (server-side, for intra-cluster migration) |
| `hauthy.allow.kerberos` | `true` | Allow Kerberos GSSAPI connections |
| `hauthy.simple.allowed.hosts` | `*` | Comma-separated hosts/IPs for Simple auth (supports `10.0.*.*` wildcards) |
| `hauthy.simple.default.user` | `hbase` | Default username for Simple auth |
| `hauthy.metrics.enabled` | `true` | Enable JMX metrics |
| `hauthy.metrics.jmx.domain` | `com.grookage.hauthy` | JMX MBean domain |

---

## Monitoring

JMX MBean: `com.grookage.hauthy:type=AuthMetrics`

| Metric | Type | Description |
|--------|------|-------------|
| `KerberosAuthSuccess` | Counter | Successful Kerberos authentications |
| `KerberosAuthFailure` | Counter | Failed Kerberos attempts |
| `SimpleAuthSuccess` | Counter | Successful Simple authentications |
| `SimpleAuthRejected` | Counter | Rejected Simple auth attempts |
| `KerberosPercentage` | Gauge | Migration progress (%) |

```bash
curl -s "http://<rs>:16030/jmx?qry=com.grookage.hauthy:*" | jq .
```

---

## Build

```bash
mvn clean package -DskipTests
```

Deploy `target/hauthy-<version>.jar` to `/usr/lib/hbase/lib/` on all HBase nodes.

**Requirements:** Java 17+, HBase 2.4.x+, Hadoop 3.3.x+. Update `pom.xml` properties to match your cluster versions.

---

## License

Apache License 2.0
