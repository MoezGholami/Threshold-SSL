#!/bin/bash

set -e
cd $(dirname "$0")

pwd
ossl_include="-I/usr/local/ssl/include"
ossl_flags="$ossl_include -L/usr/local/ssl/lib -lssl -lcrypto -ldl"
c_codes_dir="../../../../c_codes"
priv1="pr1.key"
pub1="pu1.key"
runtime_config="runtime_config.json"
c_params="c_params.txt"
this_crt="root.crt"
first_crt="1.crt"
first_digest="digest.txt"
params_python_script="../../../../helper_scripts/params_feeder_root_c_code.py"

rm -rf temp_files && mkdir temp_files

cd temp_files
gcc $ossl_include -fPIC -o ecengine.o -c "$c_codes_dir"/ecengine.c
gcc $ossl_flags -shared -o ecengine.so ecengine.o && rm ecengine.o && cp ecengine.so /tmp/ecengine.so
gcc "$c_codes_dir"/root_ca_creator.c "$c_codes_dir"/commons.c $ossl_flags -o root_ca_creator.out

openssl ecparam -genkey -name secp384r1 > "$priv1" && openssl ec -in "$priv1" -pubout > "$pub1"

cat <<EOT >> $runtime_config
{
    "engine_path" :         "/tmp/ecengine.so",
    "pubkey_path" :         "$pub1",
    "output_cert_path" :    "./$this_crt",
    "c_params_file_path":   "$c_params",
    "load_ecengine" :       true,
    "debug" :               true
}
EOT
python3 "$params_python_script" ../root_cert_parameters.json $runtime_config

printf "1010\n2020\n" > signature_pipe
touch digest_pipe
./root_ca_creator.out "$c_params"
mv digest_pipe "$first_digest"
mv "$this_crt" "$first_crt"

for i in {1..10}; do
    echo "Tyring $i / 10 ..."
    ./root_ca_creator.out "$c_params" > /dev/null
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
