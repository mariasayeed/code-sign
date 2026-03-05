#!/usr/bin/env bash
# cst_signing/pkcs11_bridge/build_bridge.sh
# ────────────────────────────────────────────────────────────────────────────
# Build the hsm_pkcs11.so PKCS#11 bridge library on Linux / WSL.
#
# Prerequisites:
#   sudo apt-get install cmake gcc libcurl4-openssl-dev libssl-dev
#
# Usage:
#   bash build_bridge.sh [Release|Debug]
#
# Output:
#   build/hsm_pkcs11.so
# ────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_TYPE="${1:-Release}"

echo "=== Building HSM PKCS#11 Bridge ==="
echo "  Build type: $BUILD_TYPE"
echo "  Source dir: $SCRIPT_DIR"

# ── Prerequisites ────────────────────────────────────────────────────────────
if ! command -v cmake &>/dev/null; then
    echo "Installing cmake …"
    sudo apt-get install -y cmake 2>/dev/null || \
    sudo yum install -y cmake 2>/dev/null || \
    { echo "ERROR: cmake not found. Install it manually."; exit 1; }
fi

if ! command -v pkg-config &>/dev/null; then
    echo "WARNING: pkg-config not found. CMake may fail to locate libcurl."
fi

# ── Configure and build ──────────────────────────────────────────────────────
BUILD_DIR="$SCRIPT_DIR/build"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake "$SCRIPT_DIR" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DBUILD_SHARED=ON

make -j"$(nproc 2>/dev/null || echo 4)"

# ── Verify output ────────────────────────────────────────────────────────────
SO="$BUILD_DIR/hsm_pkcs11.so"
if [[ ! -f "$SO" ]]; then
    echo "ERROR: Build failed — $SO not found."
    exit 1
fi

echo ""
echo "=== Build successful ==="
echo "  Library: $SO"
echo "  Size:    $(du -h "$SO" | cut -f1)"
echo ""
echo "Set environment variables then run CST:"
echo ""
echo "  export HSM_BASE=\"https://YOUR_HSM/crypto/api/v1\""
echo "  export HSM_AUTH_TOKEN=\"YOUR_JWT\""
echo "  export HSM_CSF_KEY_ID=\"<csf_publicKeyId>\""
echo "  export HSM_IMG_KEY_ID=\"<img_publicKeyId>\""
echo "  export HSM_SRK_CERT_PATH=\"$(pwd)/certs/SRK1.pem\""
echo "  export HSM_CSF_CERT_PATH=\"$(pwd)/certs/CSF.pem\""
echo "  export HSM_IMG_CERT_PATH=\"$(pwd)/certs/IMG.pem\""
echo "  export HSM_TOKEN_LABEL=\"HSM-CST\""
echo "  export HSM_TOKEN_PIN=\"changeme\""
echo ""
echo "  cst -b pkcs11 --module $SO \\"
echo "      --input hab1.csf --output csf1.bin"
echo ""
echo "Or use the sign.py orchestrator (recommended):"
echo ""
echo "  python3 cst_signing/sign.py flash.bin \\"
echo "      --approach pkcs11 \\"
echo "      --pkcs11-lib $SO \\"
echo "      --cst-path /path/to/cst \\"
echo "      --hsm-base https://YOUR_HSM/crypto/api/v1 \\"
echo "      --hsm-token YOUR_JWT \\"
echo "      --pki-base  https://YOUR_PKI/pki/api/v1 \\"
echo "      --pki-token YOUR_JWT"
