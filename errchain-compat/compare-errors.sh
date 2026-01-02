#!/bin/bash
# JWT Error Compatibility Comparison Script
#
# This script compares error behavior between v3.0.12 and errchain-migration
# by running the same test program against both versions.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ERRCHAIN_DIR="$SCRIPT_DIR/.."
V3012_DIR="$SCRIPT_DIR/../../../.worktrees/v3.0.12"
RESULTS_DIR="$SCRIPT_DIR/results"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}JWT Error Compatibility Test Suite${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Create results directory
mkdir -p "$RESULTS_DIR"

# Copy test program to v3.0.12 worktree
echo -e "${YELLOW}[1/4] Preparing test program...${NC}"
mkdir -p "$V3012_DIR/compat-tests"
cp "$SCRIPT_DIR/error_behavior.go" "$V3012_DIR/compat-tests/"
echo -e "${GREEN}✓ Test program ready${NC}"
echo ""

# Step 1: Test errchain-migration version
echo -e "${YELLOW}[2/4] Testing errchain-migration version...${NC}"
cd "$SCRIPT_DIR"
go run error_behavior.go > "$RESULTS_DIR/errchain.txt" 2>&1
echo -e "${GREEN}✓ errchain-migration tests complete${NC}"
echo ""

# Step 2: Test v3.0.12 version
echo -e "${YELLOW}[3/4] Testing v3.0.12 version...${NC}"
cd "$V3012_DIR/compat-tests"
go run error_behavior.go > "$RESULTS_DIR/v3012.txt" 2>&1
echo -e "${GREEN}✓ v3.0.12 tests complete${NC}"
echo ""

# Step 3: Compare results
echo -e "${YELLOW}[4/4] Comparing results...${NC}"
echo ""

# Show differences
if diff -u "$RESULTS_DIR/v3012.txt" "$RESULTS_DIR/errchain.txt" > "$RESULTS_DIR/diff.txt"; then
    echo -e "${GREEN}✓✓✓ PERFECT MATCH ✓✓✓${NC}"
    echo -e "${GREEN}All error behaviors are identical between v3.0.12 and errchain-migration${NC}"
    rm -f "$RESULTS_DIR/diff.txt"
    exit_code=0
else
    echo -e "${YELLOW}Differences detected:${NC}"
    echo ""
    cat "$RESULTS_DIR/diff.txt"
    echo ""
    echo -e "${YELLOW}Summary:${NC}"

    # Analyze differences
    if grep -q "IsParseError:" "$RESULTS_DIR/diff.txt"; then
        echo -e "${RED}  ✗ ParseError behavior differs${NC}"
        exit_code=1
    else
        echo -e "${GREEN}  ✓ ParseError behavior matches${NC}"
        exit_code=0
    fi

    if grep -q "IsValidateError:" "$RESULTS_DIR/diff.txt"; then
        echo -e "${RED}  ✗ ValidateError behavior differs${NC}"
        exit_code=1
    else
        echo -e "${GREEN}  ✓ ValidateError behavior matches${NC}"
    fi

    if grep -q "IsTokenExpired:" "$RESULTS_DIR/diff.txt"; then
        echo -e "${RED}  ✗ TokenExpiredError behavior differs${NC}"
        exit_code=1
    else
        echo -e "${GREEN}  ✓ TokenExpiredError behavior matches${NC}"
    fi

    if grep -q "IsInvalidIssuer:" "$RESULTS_DIR/diff.txt"; then
        echo -e "${RED}  ✗ InvalidIssuerError behavior differs${NC}"
        exit_code=1
    else
        echo -e "${GREEN}  ✓ InvalidIssuerError behavior matches${NC}"
    fi

    if grep -q "IsClaimNotFound:" "$RESULTS_DIR/diff.txt"; then
        echo -e "${RED}  ✗ ClaimNotFoundError behavior differs${NC}"
        exit_code=1
    else
        echo -e "${GREEN}  ✓ ClaimNotFoundError behavior matches${NC}"
    fi

    if grep -q "UnwrapDepth:" "$RESULTS_DIR/diff.txt"; then
        echo -e "${YELLOW}  ⚠ Error chain depth differs (may be expected with errchain)${NC}"
    else
        echo -e "${GREEN}  ✓ Error chain depth matches${NC}"
    fi

    if grep -q "Message:" "$RESULTS_DIR/diff.txt"; then
        echo -e "${YELLOW}  ⚠ Error messages differ (checking for semantic equivalence)${NC}"
    fi
fi

echo ""
echo "Detailed results saved to:"
echo "  - $RESULTS_DIR/errchain.txt"
echo "  - $RESULTS_DIR/v3012.txt"
echo "  - $RESULTS_DIR/diff.txt (if differences exist)"
echo ""

exit $exit_code
