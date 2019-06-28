#!/bin/bash

set -e
cd $(dirname "$0")

pwd
ossl_include="-I/usr/local/ssl/include"
ossl_flags="$ossl_include -L/usr/local/ssl/lib -lssl -lcrypto -ldl"
c_codes_dir="../../../../c_codes"
params_python_script="../../../../helper_scripts/params_feeder_csr.py"
priv_r="rootkey.key"
root_crt="root.crt"

priv_cl="client_pr.key"
cl_csr="client.csr"
cl_ext="../client.ext"
cl_runtime_config="cl_runtime_config.json"
c_params="c_params.txt"

this_crt="client.crt"
first_crt="1.crt"
first_digest="digest.txt"

rm -rf temp_files && mkdir temp_files

cd temp_files
gcc $ossl_include -fPIC -o ecengine.o -c "$c_codes_dir"/ecengine.c
gcc $ossl_flags -shared -o ecengine.so ecengine.o && rm ecengine.o && cp ecengine.so /tmp/ecengine.so
gcc "$c_codes_dir"/stub_signer.c $ossl_flags -o stub_signer.out
gcc "$c_codes_dir"/csr_signer.c "$c_codes_dir"/commons.c $ossl_flags -o csr_signer.out

openssl ecparam -genkey -name secp384r1 > "$priv_r"
openssl ecparam -genkey -name secp384r1 > "$priv_cl"
cp "$priv_r" /root/.rnd
openssl req -x509 -new -nodes -key "$priv_r" -sha256 -days 3660 -out "$root_crt" -subj "/C=IR/ST=Tehran/L=Tehran/O=Sparkling Network/OU=Security Department/CN=moezhome.ir/emailAddress=a_moezz@moezhome.ir"

openssl req -new -key "$priv_cl" -sha256 -out "$cl_csr" -subj "/C=US/ST=Texas/L=Austin/O=Moez Dev/OU=Security Department/CN=moez.dev/emailAddress=a_moezz@moez.dev"

cat <<EOT >> $cl_runtime_config
{
    "c_params_file_path":   "$c_params",
    "csr_path":             "$cl_csr",
    "ext_file_path":        "$cl_ext",
    "output_cert_path" :    "./$this_crt",
    "startDateASN1":        "20210101000000Z",
    "endDateASN1":          "20220101000000Z",
    "serial":               "0x12345",
    "x509v3":               true,
    "ca_cert_path":         "$root_crt",
    "engine_path" :         "/tmp/ecengine.so",
    "load_ecengine" :       true,
    "debug" :               true
}
EOT
python3 "$params_python_script" "$cl_runtime_config"


rm -rf digest_pipe signature_pipe && printf "1010\n2020\n" > signature_pipe && touch digest_pipe
./csr_signer.out "$c_params"
mv digest_pipe "$first_digest"
mv "$this_crt" "$first_crt"

for i in {1..10}; do
    echo "Tyring $i / 10 ..."
    ./csr_signer.out "$c_params" > /dev/null
    if ! diff digest_pipe "$first_digest"; then
        echo "The digests are different."
        echo "Test failed!"
        exit 1
    fi
    if ! diff "$this_crt" "$first_crt"; then
        echo "The certificates are different."
        echo "Test failed!"
        exit 1
    fi
    sleep 1
done

printf "\n\n\n"


echo "Test passed!"
exit 0
