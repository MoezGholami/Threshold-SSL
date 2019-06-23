#!/bin/bash

set -e
cd $(dirname "$0")/..
docker build . -t ossl:pre > /dev/null
#docker run -v "$(pwd)":/root ossl:pre /root/tests/run_all_tests.sh
docker run -v "$(pwd)":/root -it ossl:pre /bin/bash
