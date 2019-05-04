#!/bin/bash

ossl_include="-I/usr/local/Cellar/openssl/1.0.2r/include"
all_ossl_flags="$ossl_include -L/usr/local/Cellar/openssl/1.0.2r/lib -lssl -lcrypto"

set -e

gcc $ossl_include -fPIC -o ecengine.o -c ecengine.c
gcc $all_ossl_flags -shared -o ecengine.so ecengine.o
openssl engine -t -c `pwd`/ecengine.so

rm -f hashs.txt *.crt

frozen_time="2008-12-24 08:15:42"
cert_num=0

for i in $(seq 1 10);
do
    faketime "$frozen_time" openssl req -engine `pwd`/ecengine.so -x509 -new -key mozroot.key -sha256 -days 3660 -out mozrootca.crt -passin pass:moez -subj "/C=IR/ST=Tehran/L=Tehran/O=Moez Home/OU=Security Department/CN=moezhome.ir/emailAddress=a_moezz@moezhome.ir" -set_serial 0xdbb4cfd2b11b4926 #-rand ecengine.c
    echo "the certificate created with $? status."
    cat digest_pipe >> hashs.txt;
    diff mozrootca.crt $cert_num.crt || cert_num=$(($cert_num+1)) && cp mozrootca.crt $cert_num.crt && sleep 1
done

if [[ $cert_num -gt 1 ]]; then
    printf "\n\n\n"
    echo "There are unidentical CRTs. FAILED ..."
    echo "look at the .crt output files"
    false
fi

# for checking the difference
    # for i in $(seq 2 10); do vimdiff $(($i-1)).crt $i.crt; done
