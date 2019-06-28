#!/bin/bash

set -e
cd $(dirname "$0")/..
docker build . -t ossl:pre > /dev/null
if [ "$1" = "debug" ]; then
    docker run -v "$(pwd)":/root/lab -it ossl:pre /bin/bash
else
    docker run -v "$(pwd)":/root/lab ossl:pre /root/lab/tests/ossl_tests.sh
fi
