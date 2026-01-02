#!/bin/bash
# JWT Error Compatibility Comparison Script
#
# This script compares error behavior between v3.0.12 and errchain-migration
# by running tests against each version separately and comparing results.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ERRCHAIN_DIR="$SCRIPT_DIR/.."
V3012_DIR="$SCRIPT_DIR/../../../.worktrees/v3.0.12"
RESULTS_DIR="$SCRIPT_DIR/results"

echo -e "${YELLOW}JWT Error Compatibility Test Suite${NC}"
echo "=================================="
echo ""

# Create results directory
mkdir -p "$RESULTS_DIR"

# Step 1: Test errchain-migration version
echo -e "${YELLOW}[1/3] Testing errchain-migration version...${NC}"
cd "$ERRCHAIN_DIR"
go test -json ./jwt/... -run="TestError|TestValidat" 2>&1 | tee "$RESULTS_DIR/errchain.json"
echo -e "${GREEN}✓ errchain-migration tests complete${NC}"
echo ""

# Step 2: Test v3.0.12 version
echo -e "${YELLOW}[2/3] Testing v3.0.12 version...${NC}"
cd "$V3012_DIR"
go test -json ./jwt/... -run="TestError|TestValidat" 2>&1 | tee "$RESULTS_DIR/v3012.json"
echo -e "${GREEN}✓ v3.0.12 tests complete${NC}"
echo ""

# Step 3: Compare results
echo -e "${YELLOW}[3/3] Comparing results...${NC}"
cd "$SCRIPT_DIR"

# Simple comparison (check if same tests pass/fail)
echo "Test Results Comparison:"
echo "------------------------"

errchain_pass=$(grep -c '"Action":"pass"' "$RESULTS_DIR/errchain.json" || echo "0")
errchain_fail=$(grep -c '"Action":"fail"' "$RESULTS_DIR/errchain.json" || echo "0")
v3012_pass=$(grep -c '"Action":"pass"' "$RESULTS_DIR/v3012.json" || echo "0")
v3012_fail=$(grep -c '"Action":"fail"' "$RESULTS_DIR/v3012.json" || echo "0")

echo "errchain-migration: $errchain_pass passed, $errchain_fail failed"
echo "v3.0.12:           $v3012_pass passed, $v3012_fail failed"
echo ""

if [ "$errchain_pass" -eq "$v3012_pass" ] && [ "$errchain_fail" -eq "$v3012_fail" ]; then
    echo -e "${GREEN}✓ Test results match - error compatibility maintained${NC}"
    exit 0
else
    echo -e "${RED}✗ Test results differ - potential compatibility issue${NC}"
    echo ""
    echo "Detailed results saved to:"
    echo "  - $RESULTS_DIR/errchain.json"
    echo "  - $RESULTS_DIR/v3012.json"
    exit 1
fi
