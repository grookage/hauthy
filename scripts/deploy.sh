#!/bin/bash
#
# Deploy Hauthy to HBase cluster
#
# Usage: ./deploy.sh [--rolling]
#   --rolling: Perform rolling restart after deployment
#

set -euo pipefail

# Configuration - modify these for your environment
HBASE_LIB_DIR="${HBASE_LIB_DIR:-/usr/lib/hbase/lib}"
HBASE_CONF_DIR="${HBASE_CONF_DIR:-/etc/hbase/conf}"
REGIONSERVERS_FILE="${REGIONSERVERS_FILE:-/etc/hbase/conf/regionservers}"
MASTERS_FILE="${MASTERS_FILE:-/etc/hbase/conf/masters}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Parse arguments
ROLLING=""
if [[ "${1:-}" == "--rolling" ]]; then
    ROLLING="true"
fi

# Find JAR
JAR_PATH=$(ls "$PROJECT_DIR/target/hauthy-"*.jar 2>/dev/null | grep -v sources | grep -v javadoc | head -1)
if [[ -z "$JAR_PATH" || ! -f "$JAR_PATH" ]]; then
    log_error "JAR not found. Run ./build.sh first"
    exit 1
fi

JAR_NAME=$(basename "$JAR_PATH")
log_info "Deploying $JAR_NAME"

# Get hosts
if [[ ! -f "$REGIONSERVERS_FILE" ]]; then
    log_error "RegionServers file not found: $REGIONSERVERS_FILE"
    exit 1
fi

HOSTS=$(cat "$REGIONSERVERS_FILE")
MASTERS=""
if [[ -f "$MASTERS_FILE" ]]; then
    MASTERS=$(cat "$MASTERS_FILE")
fi

ALL_HOSTS="$HOSTS $MASTERS"
HOST_COUNT=$(echo "$ALL_HOSTS" | wc -w)

log_info "Deploying to $HOST_COUNT hosts..."

# Deploy JAR
for host in $ALL_HOSTS; do
    log_info "Deploying JAR to $host..."
    scp -q "$JAR_PATH" "${host}:${HBASE_LIB_DIR}/"
    
    if [[ $? -ne 0 ]]; then
        log_error "Failed to deploy to $host"
        exit 1
    fi
done

log_info "JAR deployment complete"

# Rolling restart if requested
if [[ "$ROLLING" == "true" ]]; then
    log_info "Performing rolling restart..."
    
    # Restart RegionServers
    for host in $HOSTS; do
        log_info "Restarting RegionServer on $host..."
        ssh "$host" "sudo systemctl restart hbase-regionserver" || {
            log_warn "systemctl failed, trying service command"
            ssh "$host" "sudo service hbase-regionserver restart"
        }
        
        # Wait for RS to come back
        log_info "  Waiting for RegionServer to start..."
        sleep 45
        
        # Verify RS is healthy
        RS_STATUS=$(ssh "$host" "systemctl is-active hbase-regionserver 2>/dev/null || echo 'unknown'")
        if [[ "$RS_STATUS" == "active" ]]; then
            log_info "  $host: RegionServer active ✓"
        else
            log_warn "  $host: RegionServer status: $RS_STATUS"
        fi
    done
    
    # Restart Masters (one at a time)
    for host in $MASTERS; do
        log_info "Restarting Master on $host..."
        ssh "$host" "sudo systemctl restart hbase-master" || {
            log_warn "systemctl failed, trying service command"
            ssh "$host" "sudo service hbase-master restart"
        }
        sleep 30
        
        MASTER_STATUS=$(ssh "$host" "systemctl is-active hbase-master 2>/dev/null || echo 'unknown'")
        if [[ "$MASTER_STATUS" == "active" ]]; then
            log_info "  $host: Master active ✓"
        else
            log_warn "  $host: Master status: $MASTER_STATUS"
        fi
    done
    
    log_info "Rolling restart complete"
fi

log_info ""
log_info "Deployment successful!"
log_info ""
log_info "Next steps:"
if [[ -z "$ROLLING" ]]; then
    log_info "  1. Update hbase-site.xml with Hauthy configuration"
    log_info "  2. Perform rolling restart: ./deploy.sh --rolling"
fi
log_info "  3. Verify with: ./verify.sh"
