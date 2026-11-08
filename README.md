# OpenSSL demo

AES-256-GCM encrypt/decrypt round trip in which every OpenSSL call is `--wrap`ped and
executed inside an isolated SDRaD execution domain. The key, IV and ciphertext buffers are
allocated in a separate SDRaD data domain that both the application and the OpenSSL domain
can access. OpenSSL is initialised and cleaned up inside its own domain.

    ./build_and_run.sh

The script clones and builds SDRaD into `../secure-rewind-and-discard` and OpenSSL
(`OpenSSL_1_1_0-stable`) into `../openssl` if they are not already there, then builds and
runs the demo.

Expected output:

    domains ready: openssl=2 openssl_data=3
    PASS: Plaintext values match!  ("This is")
    OpenSSL domain cleaned up
