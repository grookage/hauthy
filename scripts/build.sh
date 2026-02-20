#!/bin/bash
#
# Build the Hauthy JAR
#
# Usage: ./build.sh [--skip-tests]
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

SKIP_TESTS=""
if [[ "${1:-}" == "--skip-tests" ]]; then
    SKIP_TESTS="-DskipTests"
fi

echo "========================================"
echo "Building Hauthy"
echo "========================================"
echo ""

mvn clean package $SKIP_TESTS

echo ""
echo "========================================"
echo "Build Complete!"
echo "========================================"
echo ""
echo "JAR location:"
ls -la "$PROJECT_DIR/target/hauthy-"*.jar 2>/dev/null || echo "  (no JAR found)"
