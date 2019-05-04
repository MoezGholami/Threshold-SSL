ossl_flags="-I/usr/local/Cellar/openssl/1.0.2r/include -L/usr/local/Cellar/openssl/1.0.2r/lib -lssl -lcrypto"

gcc certificate_signature_changer.c $ossl_flags -o signature_changer.out
