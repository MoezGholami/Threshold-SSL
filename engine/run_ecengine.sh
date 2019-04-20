#!/bin/bash

ossl_include="-I/usr/local/Cellar/openssl/1.0.2r/include"
all_ossl_flags="$ossl_include -L/usr/local/Cellar/openssl/1.0.2r/lib -lssl -lcrypto"

set -e

gcc $ossl_include -fPIC -o ecengine.o -c ecengine.c
gcc $all_ossl_flags -shared -o ecengine.so ecengine.o
openssl engine -t -c `pwd`/ecengine.so
