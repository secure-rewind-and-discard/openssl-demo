#!/bin/bash
# Clone and build SDRaD and OpenSSL 1.1.0 if needed, then build and run the demo.
# SDRAD_DIR / OPENSSL_DIR override the locations, SDRAD_GIT / OPENSSL_GIT the clone URLs.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
SDRAD_DIR=${SDRAD_DIR:-$ROOT/secure-rewind-and-discard}
OPENSSL_DIR=${OPENSSL_DIR:-$ROOT/openssl}
SDRAD_GIT=${SDRAD_GIT:-git@github.com:secure-rewind-and-discard/secure-rewind-and-discard.git}
OPENSSL_GIT=${OPENSSL_GIT:-https://github.com/openssl/openssl.git}
OPENSSL_BRANCH=OpenSSL_1_1_0-stable
JOBS=${JOBS:-$(nproc)}

step() { printf '\n==> %s\n' "$*"; }

grep -qw pku /proc/cpuinfo || { echo "error: CPU has no Memory Protection Keys (pku); SDRaD cannot run here" >&2; exit 1; }

# SDRaD
if [ ! -f "$SDRAD_DIR/src/sdrad_api.h" ]; then
    step "Cloning SDRaD into $SDRAD_DIR"
    git clone --depth 1 "$SDRAD_GIT" "$SDRAD_DIR" \
        || git clone --depth 1 https://github.com/secure-rewind-and-discard/secure-rewind-and-discard.git "$SDRAD_DIR"
fi
step "Building libsdrad"
make -s -C "$SDRAD_DIR/src" >/dev/null 2>&1 || make -C "$SDRAD_DIR/src"
SDR=$SDRAD_DIR/src
ls "$SDR/libsdrad.so" >/dev/null

# OpenSSL 1.1.0
if [ ! -f "$OPENSSL_DIR/libcrypto.so.1.1" ]; then
    if [ ! -f "$OPENSSL_DIR/Configure" ]; then
        step "Cloning OpenSSL ($OPENSSL_BRANCH) into $OPENSSL_DIR"
        git clone --depth 1 --branch "$OPENSSL_BRANCH" "$OPENSSL_GIT" "$OPENSSL_DIR"
    fi
    step "Building OpenSSL 1.1.0"
    ( cd "$OPENSSL_DIR" && ./config shared >config.log 2>&1 \
      && { make -j"$JOBS" build_libs >build.log 2>&1 || make build_libs >>build.log 2>&1; } ) \
      || { echo "OpenSSL build failed, see $OPENSSL_DIR/build.log" >&2; exit 1; }
fi
echo "OpenSSL: $(strings "$OPENSSL_DIR/libcrypto.so.1.1" | grep -m1 '^OpenSSL 1')"

# demo
step "Building the demo"
# libsdrob is the former name of libsdrad; older libcrypto builds still list it as a dependency
mkdir -p "$HERE/shim" && ln -sfr "$SDR/libsdrad.so" "$HERE/shim/libsdrob.so"

WRAP=""
for f in BN_new BN_set_word EVP_PKEY_CTX_new_id EVP_PKEY_keygen_init EVP_PKEY_keygen EVP_PKEY_CTX_new \
         EVP_PKEY_encrypt BIO_dump_fp EVP_PKEY_decrypt EVP_PKEY_CTX_free EVP_EncryptInit_ex EVP_CIPHER_CTX_ctrl \
         __stack_chk_fail EVP_PKEY_new EVP_EncryptUpdate EVP_DecryptInit_ex EVP_DecryptUpdate EVP_DecryptFinal_ex \
         EVP_CIPHER_CTX_new EVP_PKEY_encrypt_init EVP_PKEY_decrypt_init EVP_EncryptFinal_ex EVP_CIPHER_CTX_free \
         pthread_create; do
    WRAP="$WRAP -Wl,--wrap=$f"
done

cd "$HERE"
CFLAGS="-fstack-protector-strong -g -I$OPENSSL_DIR/include -I$SDR"
gcc $CFLAGS -Wno-discarded-qualifiers -c main.c -o main.o
gcc $CFLAGS -c openssl_demo.c -o openssl_demo.o 2>/dev/null
gcc -fstack-protector-strong -g -T ./demo.ld main.o openssl_demo.o $WRAP \
    -L"$SDR" -L"$OPENSSL_DIR" -Wl,-rpath,"$OPENSSL_DIR" -lsdrad -lpthread -lcrypto -lssl -o main \
    2>&1 | grep -v 'libsdrob.so, needed' || true
[ -x ./main ]

step "Running the demo"
echo "libcrypto in use: $(ldd ./main | grep -oE '/[^ ]*libcrypto[^ ]*')"
LD_LIBRARY_PATH="$SDR:$HERE/shim" ./main
