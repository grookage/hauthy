#!/bin/bash
#
# Disable simple authentication (Kerberos only)
#
# Run this AFTER all clients have migrated to Kerberos.
# Check metrics before running: KerberosPercentage should be 100%
#

set -euo pipefail

HBASE_CONF_DIR="${HBASE_CONF_DIR:-/etc/hbase/conf}"
REGIONSERVERS_FILE="${REGIONSERVERS_FILE:-/etc/hbase/conf/regionservers}"
MASTERS_FILE="${MASTERS_FILE:-/etc/hbase/conf/masters}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check metrics first
log_info "Checking authentication metrics..."

REGIONSERVER_PORT=${REGIONSERVER_JMX_PORT:-16030}
METRICS_URL="http://localhost:$REGIONSERVER_PORT/jmx?qry=com.grookage.hauthy:*"

SIMPLE_COUNT=$(curl -s "$METRICS_URL" 2>/dev/null | grep -oP '"SimpleAuthSuccess"\s*:\s*\K[0-9]+' || echo "0")
KERBEROS_COUNT=$(curl -s "$METRICS_URL" 2>/dev/null | grep -oP '"KerberosAuthSuccess"\s*:\s*\K[0-9]+' || echo "0")
KERBEROS_PCT=$(curl -s "$METRICS_URL" 2>/dev/null | grep -oP '"KerberosPercentage"\s*:\s*\K[0-9.]+' || echo "0")

log_info "Current metrics:"
log_info "  Kerberos success: $KERBEROS_COUNT"
log_info "  Simple success: $SIMPLE_COUNT"
log_info "  Kerberos percentage: $KERBEROS_PCT%"

if [[ "$SIMPLE_COUNT" -gt 0 ]]; then
    log_warn ""
    log_warn "WARNING: There are still $SIMPLE_COUNT simple auth connections!"
    log_warn "Disabling simple auth will break these clients."
    log_warn ""
    read -p "Continue anyway? (y/N) " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_info "Aborted."
        exit 0
    fi
fi

# Get all hosts
HOSTS=$(cat "$REGIONSERVERS_FILE" 2>/dev/null || echo "localhost")
if [[ -f "$MASTERS_FILE" ]]; then
    MASTERS=$(cat "$MASTERS_FILE")
    HOSTS="$HOSTS $MASTERS"
fi

log_info "Disabling simple authentication..."

for host in $HOSTS; do
    log_info "Updating config on $host..."
    
    # Backup config
    ssh "$host" "sudo cp $HBASE_CONF_DIR/hbase-site.xml $HBASE_CONF_DIR/hbase-site.xml.backup.$(date +%Y%m%d%H%M%S)"
    
    # Update hauthy.allow.simple to false
    ssh "$host" "sudo sed -i 's|<name>hauthy.allow.simple</name>\s*<value>true</value>|<name>hauthy.allow.simple</name><value>false</value>|g' $HBASE_CONF_DIR/hbase-site.xml"
    
    log_info "  Config updated on $host"
done

log_info ""
log_info "Configuration updated!"
log_info ""
log_info "Next steps:"
log_info "  1. Perform rolling restart: ./deploy.sh --rolling"
log_info "  2. After restart, simple auth connections will be rejected"
log_info "  3. All clients must use Kerberos authentication"
