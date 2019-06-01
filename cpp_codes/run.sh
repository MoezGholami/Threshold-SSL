#!/bin/bash

ossl_flags="-I/usr/local/Cellar/openssl/1.0.2r/include -L/usr/local/Cellar/openssl/1.0.2r/lib -lssl -lcrypto"

set -e
python parameter_feed_for_c_code.py root_cert_parameters.json runtime.json
gcc root_ca_generate_from_key.c $ossl_flags -o root_ca_generate_from_key.out && ./root_ca_generate_from_key.out
