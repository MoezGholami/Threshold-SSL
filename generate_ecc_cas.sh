#!/bin/bash

set -e

rm -rf output
mkdir -p output
cd output

openssl version

echo "load curves names ..."
openssl ecparam -list_curves > open_ssl_curves.txt

echo "generate root ECC key file ..."
openssl ecparam -genkey -name secp521r1 | openssl ec -aes-256-cbc -out mozroot.key

echo "generate the root certificate file ..."
openssl req -x509 -new -nodes -key mozroot.key -sha256 -days 3660 -out mozrootca.crt


echo "generate a sample client certificate ..."
echo "generate client key file ..."
openssl ecparam -genkey -name secp521r1 | openssl ec -aes-256-cbc -out mozdev.key
echo "generate certificate request ..."
openssl req -new -key mozdev.key -out mozdev.csr
#the certificate domain info: this is a sample crt file, I don't have any clue what it means but that's fine
cat <<EOT >> mozdev.crt
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = moez.dev
EOT
echo $ext > mozdev.ext
echo "generate the client certificate ..."
openssl x509 -req -in mozdev.csr -CA mozrootca.crt -CAkey mozroot.key -CAcreateserial -sha256 \
    -out mozdev.crt -days 365 -sha256 -extfile mozdev.ext
