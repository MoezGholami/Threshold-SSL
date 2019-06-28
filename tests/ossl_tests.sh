#!/bin/bash

cd $(dirname "$0")
pwd
result=0
logs="ossl_tests_log.log"
rm -rf "$logs"

declare -a tests=(
    "root_crt_creation/validity"
    "root_crt_creation/reproducibility"
    "client_crt_creation/validity"
    "client_crt_creation/reproducibility"
)

for t in "${tests[@]}"; do
    echo "running $t ..."
    if bash "./$t/run.sh" >>"$logs" 2>&1; then
        echo "Passed!"
    else
        echo "### $t FAILED"
        echo ""
        echo ""
        result=1
    fi
done
exit $result
