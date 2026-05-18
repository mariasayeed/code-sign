#!/usr/bin/env bash
# Bootstrap dependencies for the PKCS#11 bridge on Ubuntu/Debian.
# This does NOT install NXP CST or srktool (vendor-provided).
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (e.g., sudo $0)"
  exit 1
fi

echo "== Updating apt metadata =="
apt-get update -y

# Core build toolchain and helpers
BUILD_PKGS=(
  build-essential
  cmake
  pkg-config
)

# Libraries required by the PKCS#11 bridge
LIB_PKGS=(
  libcurl4-openssl-dev
  libssl-dev
)

# Runtime libs (normally pulled in via -dev packages, but explicit for clarity)
RUNTIME_PKGS=(
  libcurl4
  libssl3
)

# Optional but commonly needed for CST PKCS#11 backend
CST_PKCS11_PKGS=(
  libengine-pkcs11-openssl
)

echo "== Installing packages =="
apt-get install -y \
  "${BUILD_PKGS[@]}" \
  "${LIB_PKGS[@]}" \
  "${RUNTIME_PKGS[@]}" \
  "${CST_PKCS11_PKGS[@]}"

echo "== Done =="
echo "Installed build deps for the PKCS#11 bridge."
echo "Reminder: Install NXP CST and srktool separately (vendor package)."
