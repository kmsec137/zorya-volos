#!/bin/bash
##############################################################################
# test_vdso_integration.sh - Test VDSO extraction and p-code generation
#
# Usage: ./test_vdso_integration.sh <binary_path>
##############################################################################

set -e

ZORYA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_PATH="$1"

if [ -z "$BIN_PATH" ]; then
    echo "Usage: $0 <binary_path>"
    exit 1
fi

echo "======================================================================"
echo "Testing VDSO Integration for: $BIN_PATH"
echo "======================================================================"

# Get entry point
ENTRY_POINT=$(readelf -h "$BIN_PATH" | awk '/Entry point address:/ {print $NF}')
echo "Entry point: $ENTRY_POINT"

# Step 1: Extract VDSO
echo ""
echo "[1/3] Extracting VDSO..."
"$ZORYA_DIR/scripts/extract_vdso.sh" "$BIN_PATH" "$ENTRY_POINT"

# Check if extraction succeeded
VDSO_SO="$ZORYA_DIR/results/initialization_data/vdso/vdso.so"
VDSO_BASE_FILE="$ZORYA_DIR/results/initialization_data/vdso/vdso_base_addr.txt"

if [ ! -f "$VDSO_SO" ] || [ ! -f "$VDSO_BASE_FILE" ]; then
    echo "[ERROR] VDSO extraction failed"
    exit 1
fi

echo "VDSO extracted: $VDSO_SO"

# Get VDSO base address
VDSO_BASE=$(cat "$VDSO_BASE_FILE")
echo "VDSO base address: $VDSO_BASE"

# Check VDSO file size
VDSO_SIZE=$(stat -c%s "$VDSO_SO")
echo "VDSO size: $VDSO_SIZE bytes"

# Step 2: Generate p-code for VDSO
echo ""
echo "[2/3] Generating P-Code for VDSO..."
"$ZORYA_DIR/scripts/generate_vdso_pcode.sh" "$VDSO_SO" "$VDSO_BASE"

# Check if p-code generation succeeded
VDSO_PCODE="$ZORYA_DIR/results/initialization_data/vdso/vdso_low_pcode.txt"

if [ ! -f "$VDSO_PCODE" ]; then
    echo "[ERROR] VDSO P-Code generation failed"
    exit 1
fi

echo "VDSO P-Code generated: $VDSO_PCODE"

# Count instructions
INSTR_COUNT=$(grep -c "^0x" "$VDSO_PCODE" || true)
echo "Number of instruction blocks: $INSTR_COUNT"

# Step 3: Analyze VDSO p-code content
echo ""
echo "[3/3] Analyzing VDSO p-code..."

# Show sample addresses
echo "Sample VDSO addresses:"
grep "^0x" "$VDSO_PCODE" | head -5

# Show common VDSO functions
echo ""
echo "Checking for common VDSO functions..."
for func in "__vdso_clock_gettime" "__vdso_gettimeofday" "__vdso_time" "__vdso_getcpu"; do
    if grep -q "$func" "$VDSO_PCODE" 2>/dev/null; then
        echo "  ✓ Found: $func"
    fi
done

echo ""
echo "======================================================================"
echo "VDSO Integration Test PASSED!"
echo "======================================================================"
echo ""
echo "Summary:"
echo "  - VDSO extracted: $VDSO_SO ($VDSO_SIZE bytes)"
echo "  - Base address: $VDSO_BASE"
echo "  - P-code blocks: $INSTR_COUNT"
echo "  - P-code file: $VDSO_PCODE"
echo ""
echo "You can now run Zorya, and it will automatically merge VDSO p-code"
echo "into the execution map, allowing execution of VDSO functions."

