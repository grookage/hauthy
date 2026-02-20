#!/bin/bash
#
# Enable Hauthy dual-mode authentication in HBase configuration
#
# This script adds the necessary configuration properties to hbase-site.xml
#

set -euo pipefail

HBASE_CONF_DIR="${HBASE_CONF_DIR:-/etc/hbase/conf}"
REGIONSERVERS_FILE="${REGIONSERVERS_FILE:-/etc/hbase/conf/regionservers}"
MASTERS_FILE="${MASTERS_FILE:-/etc/hbase/conf/masters}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

HAUTHY_CONFIG='
    <!-- Hauthy Dual-Mode Authentication -->
    <property>
        <name>hauthy.enabled</name>
        <value>true</value>
        <description>Enable dual-mode authentication (Kerberos + Simple)</description>
    </property>
    <property>
        <name>hauthy.allow.simple</name>
        <value>true</value>
        <description>Allow simple (unauthenticated) connections during migration</description>
    </property>
    <property>
        <name>hauthy.allow.kerberos</name>
        <value>true</value>
        <description>Allow Kerberos authenticated connections</description>
    </property>
    <property>
        <name>hauthy.simple.default.user</name>
        <value>hbase</value>
        <description>Default user for simple auth connections</description>
    </property>
    <property>
        <name>hauthy.metrics.enabled</name>
        <value>true</value>
        <description>Enable authentication metrics</description>
    </property>
    
    <!-- Hauthy Coprocessor -->
    <property>
        <name>hbase.coprocessor.master.classes</name>
        <value>com.grookage.hauthy.coprocessor.HauthyCoprocessor</value>
    </property>
    <property>
        <name>hbase.coprocessor.regionserver.classes</name>
        <value>com.grookage.hauthy.coprocessor.HauthyCoprocessor</value>
    </property>
'

# Get all hosts
HOSTS=$(cat "$REGIONSERVERS_FILE" 2>/dev/null || echo "localhost")
if [[ -f "$MASTERS_FILE" ]]; then
    MASTERS=$(cat "$MASTERS_FILE")
    HOSTS="$HOSTS $MASTERS"
fi

log_info "Enabling Hauthy dual-mode authentication..."

for host in $HOSTS; do
    log_info "Updating config on $host..."
    
    # Check if already configured
    if ssh "$host" "grep -q 'hauthy.enabled' $HBASE_CONF_DIR/hbase-site.xml 2>/dev/null"; then
        log_warn "  Hauthy already configured on $host, skipping"
        continue
    fi
    
    # Backup config
    ssh "$host" "sudo cp $HBASE_CONF_DIR/hbase-site.xml $HBASE_CONF_DIR/hbase-site.xml.backup.$(date +%Y%m%d%H%M%S)"
    
    # Add Hauthy config before </configuration>
    ssh "$host" "sudo sed -i 's|</configuration>|$HAUTHY_CONFIG\n</configuration>|' $HBASE_CONF_DIR/hbase-site.xml"
    
    log_info "  Config updated on $host"
done

log_info ""
log_info "Configuration updated!"
log_info ""
log_info "Next steps:"
log_info "  1. Review the configuration changes"
log_info "  2. Perform rolling restart: ./deploy.sh --rolling"
