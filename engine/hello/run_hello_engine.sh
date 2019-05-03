#!/bin/bash

ossl_include="-I/usr/local/Cellar/openssl/1.0.2r/include"
all_ossl_flags="$ossl_include -L/usr/local/Cellar/openssl/1.0.2r/lib -lssl -lcrypto"

set -e

gcc $ossl_include -fPIC -o hello_engine.o -c hello.c
gcc $all_ossl_flags -shared -o hello_engine.so hello_engine.o
openssl engine -t -c `pwd`/hello_engine.so
