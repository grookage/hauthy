#!/bin/bash
#
# Verify Hauthy deployment and configuration
#

set -euo pipefail

# Configuration
HBASE_LIB_DIR="${HBASE_LIB_DIR:-/usr/lib/hbase/lib}"
HBASE_CONF_DIR="${HBASE_CONF_DIR:-/etc/hbase/conf}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_fail() { echo -e "${RED}[✗]${NC} $1"; }

echo "========================================"
echo "Hauthy Verification"
echo "========================================"
echo ""

# Check JAR deployment
log_info "Checking JAR deployment..."
if ls "$HBASE_LIB_DIR"/hauthy-*.jar &>/dev/null; then
    JAR=$(ls "$HBASE_LIB_DIR"/hauthy-*.jar | head -1)
    log_success "JAR found: $JAR"
else
    log_fail "JAR not found in $HBASE_LIB_DIR"
fi

# Check configuration
log_info "Checking configuration..."
if [[ -f "$HBASE_CONF_DIR/hbase-site.xml" ]]; then
    if grep -q "hauthy.enabled" "$HBASE_CONF_DIR/hbase-site.xml"; then
        ENABLED=$(grep -A1 "hauthy.enabled" "$HBASE_CONF_DIR/hbase-site.xml" | grep -oP '(?<=<value>).*(?=</value>)' || echo "unknown")
        if [[ "$ENABLED" == "true" ]]; then
            log_success "Hauthy enabled in configuration"
        else
            log_warn "Hauthy disabled in configuration (hauthy.enabled=$ENABLED)"
        fi
    else
        log_warn "hauthy.enabled not found in hbase-site.xml"
    fi
else
    log_fail "hbase-site.xml not found"
fi

# Check JMX metrics
log_info "Checking JMX metrics..."
REGIONSERVER_PORT=${REGIONSERVER_JMX_PORT:-16030}
METRICS_URL="http://localhost:$REGIONSERVER_PORT/jmx?qry=com.grookage.hauthy:*"

if curl -s "$METRICS_URL" 2>/dev/null | grep -q "AuthMetrics"; then
    log_success "AuthMetrics MBean found"
    
    # Extract metrics
    METRICS=$(curl -s "$METRICS_URL" 2>/dev/null)
    echo ""
    echo "Current metrics:"
    echo "$METRICS" | grep -E "(KerberosAuthSuccess|SimpleAuthSuccess|KerberosPercentage)" | head -10 || true
else
    log_warn "AuthMetrics MBean not found (RegionServer may not have Hauthy loaded yet)"
fi

# Check HBase status
log_info "Checking HBase status..."
if command -v hbase &>/dev/null; then
    if echo "status 'simple'" | hbase shell -n 2>&1 | grep -q "servers"; then
        log_success "HBase cluster is healthy"
    else
        log_warn "Could not verify HBase status"
    fi
else
    log_warn "hbase command not found"
fi

echo ""
echo "========================================"
echo "Verification Complete"
echo "========================================"
