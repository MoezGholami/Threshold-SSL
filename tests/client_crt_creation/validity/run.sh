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
cl_csr="../client.csr"
cl_ext="../client.ext"
cl_runtime_config="cl_runtime_config.json"
c_params="c_params.txt"

ok_crt="ok.crt"
corrupt_crt="corrupt.crt"

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

cat <<EOT >> $cl_runtime_config
{
    "c_params_file_path":   "$c_params",
    "csr_path":             "$cl_csr",
    "ext_file_path":        "$cl_ext",
    "output_cert_path" :    "./$corrupt_crt",
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


rm -rf digest_pipe signature_pipe && mkfifo digest_pipe signature_pipe
./stub_signer.out & ./csr_signer.out "$c_params"
cp "$corrupt_crt" "$ok_crt"

rm -rf digest_pipe signature_pipe
printf "1010\n2020\n" > signature_pipe && touch digest_pipe
./csr_signer.out "$c_params"
cp "$corrupt_crt" "$ok_crt"

openssl verify -check_ss_sig -CAfile "$root_crt" "$ok_crt" >ok_out.txt 2>&1 || true
openssl verify -check_ss_sig -CAfile "$root_crt" "$corrupt_crt" >corrupt_out.txt 2>&1 || true

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
