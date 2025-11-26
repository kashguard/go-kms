#!/bin/bash
# Build OpenSSL + SoftHSM with Ed25519 support inside dev container
set -euo pipefail

OPENSSL_VERSION="${OPENSSL_VERSION:-3.2.2}"
SOFTHSM_VERSION="${SOFTHSM_VERSION:-2.6.1}"
# Use user-writable directory to avoid permission issues
OPENSSL_PREFIX="${OPENSSL_PREFIX:-$HOME/openssl-ed25519}"
SOFTHSM_PREFIX="${SOFTHSM_PREFIX:-$HOME/softhsm-ed25519}"

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)
        OPENSSL_TARGET="linux-x86_64"
        ;;
    aarch64|arm64)
        OPENSSL_TARGET="linux-aarch64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

echo "Installing build dependencies (if needed)..."
# Check if autotools are available
if command -v autoreconf >/dev/null 2>&1 && command -v libtoolize >/dev/null 2>&1 && command -v automake >/dev/null 2>&1; then
    echo "Build tools already available, skipping dependency installation"
else
    echo "Installing autotools and build dependencies..."
    apt-get update 2>&1 | grep -v "Permission denied" || echo "Note: Some packages may already be installed"
    apt-get install -y build-essential perl libtool pkg-config automake m4 autoconf libsqlite3-dev bison flex wget git 2>&1 | grep -v "Permission denied" || echo "Note: Some dependencies may need manual installation"
fi

WORKDIR="$(pwd)"
TMP_DIR="$WORKDIR/tmp/softhsm-build"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

OPENSSL_SRC="$TMP_DIR/openssl"
SOFTHSM_SRC="$TMP_DIR/softhsm"
mkdir -p "$OPENSSL_SRC" "$SOFTHSM_SRC"

echo "Downloading OpenSSL ${OPENSSL_VERSION}..."
curl -sSL "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" -o "$TMP_DIR/openssl.tar.gz"
tar -xzf "$TMP_DIR/openssl.tar.gz" -C "$TMP_DIR"

echo "Building OpenSSL..."
cd "$TMP_DIR/openssl-${OPENSSL_VERSION}"
./Configure --prefix="$OPENSSL_PREFIX" "$OPENSSL_TARGET" shared
make -j"$(nproc)"
make install_sw
# Ensure library files are in the lib directory
if [ ! -f "$OPENSSL_PREFIX/lib/libcrypto.so.3" ] && [ -f "$TMP_DIR/openssl-${OPENSSL_VERSION}/libcrypto.so.3" ]; then
    echo "Copying OpenSSL libraries to install directory..."
    mkdir -p "$OPENSSL_PREFIX/lib"
    cp "$TMP_DIR/openssl-${OPENSSL_VERSION}/libcrypto.so"* "$TMP_DIR/openssl-${OPENSSL_VERSION}/libssl.so"* "$OPENSSL_PREFIX/lib/" 2>/dev/null || true
fi

echo "Downloading SoftHSM ${SOFTHSM_VERSION}..."
# Download from source archive (softhsm/SoftHSMv2 repository)
curl -sSLf "https://github.com/softhsm/SoftHSMv2/archive/refs/tags/${SOFTHSM_VERSION}.tar.gz" -o "$TMP_DIR/softhsm.tar.gz"

# Verify downloaded file (check if it's a valid gzip by trying to list contents)
if ! tar -tzf "$TMP_DIR/softhsm.tar.gz" >/dev/null 2>&1; then
    echo "Error: Downloaded file is not a valid gzip archive"
    head -20 "$TMP_DIR/softhsm.tar.gz"
    exit 1
fi

tar -xzf "$TMP_DIR/softhsm.tar.gz" -C "$TMP_DIR"

echo "Building SoftHSM..."
# Find the extracted directory (could be SoftHSMv2-2.6.1 or SoftHSMv2-2.6.1 depending on source)
SOFTHSM_DIR=$(find "$TMP_DIR" -maxdepth 1 -type d -name "SoftHSMv2-*" | head -1)
if [ -z "$SOFTHSM_DIR" ]; then
    echo "Error: Could not find extracted SoftHSM directory"
    ls -la "$TMP_DIR"
    exit 1
fi
cd "$SOFTHSM_DIR"

# Generate configure script if needed (for source archive downloads)
if [ ! -f "./configure" ]; then
    echo "Generating configure script..."
    ./autogen.sh || autoreconf -i
fi

# Configure with rpath to ensure it links to our custom OpenSSL
PKG_CONFIG_PATH="${OPENSSL_PREFIX}/lib/pkgconfig" \
LDFLAGS="-Wl,-rpath,${OPENSSL_PREFIX}/lib" \
./configure \
  --prefix="$SOFTHSM_PREFIX" \
  --with-openssl="$OPENSSL_PREFIX" \
  --with-objectstore-backend=file \
  --enable-ecc \
  --enable-eddsa
make -j"$(nproc)"
make install

echo "Installing libsofthsm2.so to /usr/lib/softhsm..."
if command -v sudo >/dev/null 2>&1; then
    sudo mkdir -p /usr/lib/softhsm
    sudo cp "$SOFTHSM_PREFIX/lib/softhsm/libsofthsm2.so" /usr/lib/softhsm/libsofthsm2.so
    sudo ldconfig
else
    mkdir -p /usr/lib/softhsm
    cp "$SOFTHSM_PREFIX/lib/softhsm/libsofthsm2.so" /usr/lib/softhsm/libsofthsm2.so
    ldconfig
fi

echo "SoftHSM with Ed25519 support installed successfully."

