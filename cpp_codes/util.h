#ifndef __openssl_threshold_util_file__
#define __openssl_threshold_util_file__

#include <stdio.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>

typedef     char    bool;
#define     true            1
#define     false           0
#ifndef     NULL
#define     NULL            0
#endif

ssize_t getline_trim(char **lineptr, size_t *n, FILE *f);
bool read_boolean_pointer(FILE *f, bool *result);
bool consume_line_till_end(FILE *f);

bool load_public_key(EVP_PKEY **pukey, BIO *bio_err, const char *pubkey_path);
EVP_PKEY *forge_dummy_private_key_from_public(EVP_PKEY *pukey);
bool writeout_certificate_file(X509 *x509, BIO *bio_err, const char *path);

#endif
