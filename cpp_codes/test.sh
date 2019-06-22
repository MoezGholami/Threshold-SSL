#!/bin/bash

PRIV_KEY_FILE="rootkey.key"
PUB_KEY_FILE="pukey.key"
DIGEST_HASH_OUTPUT_FILE_NAME="digest_pipe"
SIGNATURE_INPUT_FILE_NAME="signature_pipe"
TEMP_RUNTIME_CONFIG="truntime.json"
C_READABLE_PARAMETERS="./.c_parameters.txt"

ossl_flags="-I/usr/local/Cellar/openssl/1.0.2r/include -L/usr/local/Cellar/openssl/1.0.2r/lib -lssl -lcrypto"

set -e

rm -rf $PRIV_KEY_FILE $PUB_KEY_FILE $DIGEST_HASH_OUTPUT_FILE_NAME $SIGNATURE_INPUT_FILE_NAME $TEMP_RUNTIME_CONFIG

cat <<EOT >> $TEMP_RUNTIME_CONFIG
{
    "engine_path" :         "/Users/moez/Desktop/ssl_playground/cpp_codes/ecengine.so",
    "pubkey_path" :         "/Users/moez/Desktop/ssl_playground/cpp_codes/$PUB_KEY_FILE",
    "output_cert_path" :    "./rootcert.crt",
    "c_params_file_path":   "$C_READABLE_PARAMETERS",
    "load_ecengine" :       true,
    "debug" :               true
}
EOT


openssl ecparam -genkey -name secp256k1 > "$PRIV_KEY_FILE"
openssl ec -in "$PRIV_KEY_FILE" -pubout > "$PUB_KEY_FILE"
python parameter_feed_for_c_code.py root_cert_parameters.json $TEMP_RUNTIME_CONFIG
mkfifo $DIGEST_HASH_OUTPUT_FILE_NAME $SIGNATURE_INPUT_FILE_NAME

gcc stub_signer.c $ossl_flags -o stub_signer.out || exit
./stub_signer.out &
gcc root_ca_generate_from_key.c util.c $ossl_flags -o root_ca_generate_from_key.out &&
    ./root_ca_generate_from_key.out "$C_READABLE_PARAMETERS"
openssl verify -check_ss_sig rootcert.crt
