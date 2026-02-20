# Hauthy - HBase Dual-Mode Authentication

Hauthy enables **zero-downtime migration** from unauthenticated HBase clusters to Kerberos authentication by supporting
both authentication modes simultaneously.

## Features

- **Dual-Mode Authentication**: Accept both Kerberos and Simple auth connections
- **Zero Downtime**: Only rolling restarts required, no service interruption
- **Seamless Replication**: Bi-directional replication works throughout migration
- **Migration Metrics**: JMX metrics to track migration progress
- **Host Restrictions**: Optionally limit simple auth to specific hosts
- **Gradual Migration**: Clients migrate at their own pace

## Quick Start

### 1. Build

```bash
cd scripts
./build.sh
```

### 2. Deploy

```bash
# Deploy JAR to all nodes
./deploy.sh

# Enable dual-mode in configuration
./enable-dual-mode.sh

# Rolling restart
./deploy.sh --rolling
```

### 3. Verify

```bash
./verify.sh
```

### 4. Monitor Migration

Access JMX metrics:

```
http://<regionserver>:16030/jmx?qry=com.grookage.hauthy:*
```

Key metric: `KerberosPercentage` - target is 100% before disabling simple auth.

### 5. Complete Migration

Once all clients are on Kerberos:

```bash
./disable-simple-mode.sh
./deploy.sh --rolling
```

## Configuration

Add to `hbase-site.xml`:

```xml
<!-- Enable Hauthy -->
<property>
    <name>hauthy.enabled</name>
    <value>true</value>
</property>

        <!-- Allow both auth modes during migration -->
<property>
<name>hauthy.allow.simple</name>
<value>true</value>
</property>
<property>
<name>hauthy.allow.kerberos</name>
<value>true</value>
</property>

        <!-- Optional: Restrict simple auth to specific hosts -->
<property>
<name>hauthy.simple.allowed.hosts</name>
<value>10.0.1.*,10.0.2.*</value>
</property>

        <!-- Load Hauthy coprocessor -->
<property>
<name>hbase.coprocessor.master.classes</name>
<value>com.grookage.hauthy.coprocessor.HauthyCoprocessor</value>
</property>
<property>
<name>hbase.coprocessor.regionserver.classes</name>
<value>com.grookage.hauthy.coprocessor.HauthyCoprocessor</value>
</property>
```

See `conf/` directory for complete configuration examples.

## Configuration Properties

| Property                      | Default | Description                                                         |
|-------------------------------|---------|---------------------------------------------------------------------|
| `hauthy.enabled`              | `false` | Enable dual-mode authentication                                     |
| `hauthy.allow.simple`         | `true`  | Allow simple (unauthenticated) connections                          |
| `hauthy.allow.kerberos`       | `true`  | Allow Kerberos connections                                          |
| `hauthy.simple.allowed.hosts` | `*`     | Hosts allowed for simple auth (comma-separated, supports wildcards) |
| `hauthy.simple.default.user`  | `hbase` | Default user for simple auth                                        |
| `hauthy.simple.user.mapping`  | `true`  | Extract username from simple auth requests                          |
| `hauthy.metrics.enabled`      | `true`  | Enable JMX metrics                                                  |

## Metrics

JMX MBean: `com.grookage.hauthy:type=AuthMetrics`

| Metric                | Description                                    |
|-----------------------|------------------------------------------------|
| `KerberosAuthSuccess` | Count of successful Kerberos authentications   |
| `KerberosAuthFailure` | Count of failed Kerberos attempts              |
| `SimpleAuthSuccess`   | Count of successful simple authentications     |
| `SimpleAuthRejected`  | Count of rejected simple attempts              |
| `TotalConnections`    | Total connections processed                    |
| `ActiveConnections`   | Currently active connections                   |
| `KerberosPercentage`  | Percentage using Kerberos (migration progress) |

## Migration Guide

### Phase 1: Preparation

1. Set up KDC infrastructure
2. Create service principals and keytabs
3. Build and test Hauthy in staging

### Phase 2: Enable Dual-Mode

1. Deploy Hauthy JAR to all nodes
2. Update configuration
3. Rolling restart cluster

### Phase 3: Migrate Clients

1. Update client configurations for Kerberos
2. Clients restart at their convenience
3. Monitor `KerberosPercentage` metric

### Phase 4: Disable Simple Auth

1. Verify `KerberosPercentage` is 100%
2. Set `hauthy.allow.simple=false`
3. Rolling restart cluster

## Requirements

- HBase 2.4+
- Hadoop 3.3+
- Java 17

## Building from Source

```bash
mvn clean package
```

Run tests:

```bash
mvn test
```

LICENSE
-------

Copyright 2026 Koushik R <rkoushik.14@gmail.com>.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
