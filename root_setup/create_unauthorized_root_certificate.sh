# Feel free to change this file. The modifications are ignored. (git update-index --assume-unchanged).

#!/bin/bash

. ../constants.sh
phony_passphrase="dashfllhlhg"
pr_key_location="./temp_files/unauthorized_root_private.key"
unauthorized_crt_location="./temp_files/unauthorized_root_certificate.crt"

set -e
echo "Generating phony key on curve $CURV"
openssl ecparam -genkey -name $CURV | openssl ec -aes-256-cbc -passout pass:$phony_passphrase -out $pr_key_location
echo "Key is generated"

openssl req -x509 -new -nodes -key $pr_key_location -sha256 -days 3660 -out $unauthorized_crt_location -passin pass:$phony_passphrase -subj "/C=IR/ST=Tehran/L=Tehran/O=Sparkling Network/OU=Security Department/CN=moezhome.ir/emailAddress=a_moezz@moezhome.ir"
echo "Unauthorized certificate is generated"
