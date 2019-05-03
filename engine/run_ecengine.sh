#!/bin/bash

ossl_include="-I/usr/local/Cellar/openssl/1.0.2r/include"
all_ossl_flags="$ossl_include -L/usr/local/Cellar/openssl/1.0.2r/lib -lssl -lcrypto"

set -e

gcc $ossl_include -fPIC -o ecengine.o -c ecengine.c
gcc $all_ossl_flags -shared -o ecengine.so ecengine.o
openssl engine -t -c `pwd`/ecengine.so

set +e

for i in $(seq 1 100);
do
    openssl req -engine `pwd`/ecengine.so -x509 -new -key mozroot.key -sha256 -days 3660 -out mozrootca.crt -passin pass:moez -subj "/C=IR/ST=Tehran/L=Tehran/O=Sparkling Network/OU=Security Department/CN=moezhome.ir/emailAddress=a_moezz@moezhome.ir" -set_serial 0xdbb4cfd2b11b4926 -rand ecengine.c || true;
    cat digest_pipe >> hashs.txt;
done
