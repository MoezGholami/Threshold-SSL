#!/bin/bash

ossl_include="-I/usr/local/Cellar/openssl/1.0.2r/include"
all_ossl_flags="$ossl_include -L/usr/local/Cellar/openssl/1.0.2r/lib -lssl -lcrypto"

set -e

echo "*** compile custom md5 implementation ..."
gcc -fPIC -o rfc1321/md5c.o -c rfc1321/md5c.c

echo "*** compile our engine ..."
gcc $ossl_include -fPIC -o md5_engine.o -c md5.c

echo "*** build our engine eniterly ..."
gcc $all_ossl_flags -shared -o md5_engine.so md5_engine.o rfc1321/md5c.o

echo "*** dry run our engine ..."
openssl engine -t -c `pwd`/md5_engine.so

printf "\n\n\n"
echo "*** md5 hash \"hello world\" with our md5 engine ..."
message="hello world"
echo "$message" | openssl dgst -engine `pwd`/md5_engine.so -md5
echo "*** md5 hash \"hello world\" with the *default* md5 engine ..."
echo "$message" | openssl dgst -md5
echo "*** please visually compare the results. ..."
