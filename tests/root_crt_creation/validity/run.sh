#!/bin/bash

set -e
cd $(dirname "$0")

pwd
ossl_include="-I/usr/local/ssl/include"
ossl_flags="$ossl_include -L/usr/local/ssl/lib -lssl -lcrypto -ldl"
c_codes_dir="../../../../c_codes"
priv1="rootkey.key"
priv2="pr2.key"
pub1="pu1.key"
pub2="pu2.key"
ok_runtime_config="ok_runtime_config.json"
ok_c_params="ok_c_params.txt"
ok_crt="ok.crt"
corrupt_runtime_config="corrupt_runtime_config.json"
corrupt_c_params="corrupt_c_params.txt"
corrupt_crt="corrupt.crt"
params_python_script="../../../../helper_scripts/params_feeder_root_c_code.py"

rm -rf temp_files && mkdir temp_files

cd temp_files
gcc $ossl_include -fPIC -o ecengine.o -c "$c_codes_dir"/ecengine.c
gcc $ossl_flags -shared -o ecengine.so ecengine.o && rm ecengine.o && cp ecengine.so /tmp/ecengine.so
gcc "$c_codes_dir"/stub_signer.c $ossl_flags -o stub_signer.out
gcc "$c_codes_dir"/root_ca_generate_from_key.c "$c_codes_dir"/commons.c $ossl_flags -o root_ca_generate_from_key.out

openssl ecparam -genkey -name secp384r1 > "$priv1" && openssl ec -in "$priv1" -pubout > "$pub1"
openssl ecparam -genkey -name secp384r1 > "$priv2" && openssl ec -in "$priv2" -pubout > "$pub2" && rm -f "$priv2"

cat <<EOT >> $ok_runtime_config
{
    "engine_path" :         "/tmp/ecengine.so",
    "pubkey_path" :         "$pub1",
    "output_cert_path" :    "./$ok_crt",
    "c_params_file_path":   "$ok_c_params",
    "load_ecengine" :       true,
    "debug" :               true
}
EOT
python3 "$params_python_script" ../root_cert_parameters.json $ok_runtime_config

cat <<EOT >> $corrupt_runtime_config
{
    "engine_path" :         "/tmp/ecengine.so",
    "pubkey_path" :         "$pub2",
    "output_cert_path" :    "./$corrupt_crt",
    "c_params_file_path":   "$corrupt_c_params",
    "load_ecengine" :       true,
    "debug" :               true
}
EOT
python3 "$params_python_script" ../root_cert_parameters.json $corrupt_runtime_config

rm -rf digest_pipe signature_pipe && mkfifo digest_pipe signature_pipe
./stub_signer.out & ./root_ca_generate_from_key.out "$ok_c_params"
rm -rf digest_pipe signature_pipe && mkfifo digest_pipe signature_pipe
./stub_signer.out & ./root_ca_generate_from_key.out "$corrupt_c_params"

openssl verify -check_ss_sig ok.crt >ok_out.txt 2>&1 || true
openssl verify -check_ss_sig corrupt.crt >corrupt_out.txt 2>&1 || true

printf "\n\n\n"

result=0
if grep "certificate signature failure" corrupt_out.txt > /dev/null; then
    echo "the corrupt certificate is marked as corrupt :)"
else
    echo "False positive: the CORRUPT certificate is NOT marked as CORRUPT"
    result=1
fi

if grep "certificate signature failure" ok_out.txt > /dev/null; then
    echo "False negative: the OK certificate is marked as CORRUPT"
    result=1
else
    echo "the OK certificate is marked as OK :)"
fi

printf "\n\n\n"

if [ $result -ne 0 ]; then
    echo "Test failed!"
else
    echo "Test passed!"
fi

exit $result
