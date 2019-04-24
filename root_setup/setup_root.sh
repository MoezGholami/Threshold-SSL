#!/bin/bash


# main outputs of this part must be the signed root certificate
    # rootcert.crt
# If it's not phony, the parties information should be ready too

. ../constants.sh
PHONY=true

set -e

bash ./create_unauthorized_root_certificate.sh
