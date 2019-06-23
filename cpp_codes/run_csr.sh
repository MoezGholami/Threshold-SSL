#!/bin/bash

ossl_flags="-I/usr/local/Cellar/openssl/1.0.2r/include -L/usr/local/Cellar/openssl/1.0.2r/lib -lssl -lcrypto"

set -e

gcc stub_signer.c $ossl_flags -o stub_signer.out || exit
./stub_signer.out &
gcc csr_signer.c util.c $ossl_flags -o csr_signer.out && ./csr_signer.out client_certificate_parameters.txt
