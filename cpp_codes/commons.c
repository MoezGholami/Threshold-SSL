#include "commons.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>

ssize_t getline_trim(char **lineptr, size_t *n, FILE *f) {
    ssize_t length = getline(lineptr, n, f);
    if(length>0)
        (*lineptr)[length-1] = '\0';
    return length;
}

bool read_boolean_pointer(FILE *f, bool *result) {
    int bool_as_int = 0;
    if(fscanf(f, "%i", &bool_as_int) < 1)
        return false;
    if(!consume_line_till_end(f))
        return false;
    *result = !(!bool_as_int);
    return true;
}

bool consume_line_till_end(FILE *f) {
    char *temp_buffer = 0;
    size_t limit = 0;
    if(getline(&temp_buffer, &limit, f) <= 0)
        return false;
    free(temp_buffer);
    return true;
}

bool load_public_key(EVP_PKEY **pukey, BIO *bio_err, const char *pubkey_path) {
    EVP_PKEY *pk = NULL;
    FILE    *fp;

    if (! (fp = fopen (pubkey_path, "r"))) {
        BIO_printf(bio_err, "ERROR: Error reading CA public key file.\n");
        return false;
    }
    PEM_read_PUBKEY( fp, &pk, NULL, NULL);
    if (!pk) {
        BIO_printf(bio_err, "ERROR: Error importing key content from file.\n");
        return false;
    }
    if (fclose(fp)) {
        BIO_printf(bio_err, "ERROR: Error in closing key content file.\n");
        return false;
    }

    *pukey = pk;
    return true;
}

bool load_csr(X509_REQ **csr, BIO *bio_err, const char *path) {
    X509_REQ *request = NULL;
    FILE    *fp;

    if (! (fp = fopen (path, "r"))) {
        BIO_printf(bio_err, "ERROR: Error reading certificate request file.\n");
        return false;
    }
    PEM_read_X509_REQ( fp, &request, NULL, NULL);
    if (!request) {
        BIO_printf(bio_err, "ERROR: Error importing certificate request content from file.\n");
        return false;
    }
    if (fclose(fp)) {
        BIO_printf(bio_err, "ERROR: Error in closing certificate request file.\n");
        return false;
    }

    *csr = request;
    return true;
}

bool load_crt(X509 **crt, BIO *bio_err, const char *path) {
    X509 *certificate = NULL;
    FILE    *fp;

    if (! (fp = fopen (path, "r"))) {
        BIO_printf(bio_err, "ERROR: Error reading root certificate file.\n");
        return false;
    }
    PEM_read_X509( fp, &certificate, NULL, NULL);
    if (!certificate) {
        BIO_printf(bio_err, "ERROR: Error importing root certificate content from file.\n");
        return false;
    }
    if (fclose(fp)) {
        BIO_printf(bio_err, "ERROR: Error in closing root certificate file.\n");
        return false;
    }

    *crt = certificate;
    return true;
}

EVP_PKEY *forge_dummy_private_key_from_public(EVP_PKEY *pukey) {
    EVP_PKEY *result = NULL;
    EC_KEY *ec_key = NULL;
    BIGNUM *phony_private_integer = NULL;

    if(BN_hex2bn(&phony_private_integer, "101")==0 || !phony_private_integer)
        return NULL;
    ec_key = EVP_PKEY_get1_EC_KEY(pukey);
    if(!ec_key) {
        BN_clear_free(phony_private_integer);
        return NULL;
    }
    if(!EC_KEY_set_private_key(ec_key, phony_private_integer)) {
        BN_clear_free(phony_private_integer);
        EC_KEY_free(ec_key);
        return NULL;
    }
    result = EVP_PKEY_new();
    if(!result) {
        BN_clear_free(phony_private_integer);
        EC_KEY_free(ec_key);
    }
    if(!EVP_PKEY_set1_EC_KEY(result, ec_key)) {
        EVP_PKEY_free(result);
        result = NULL;
    }
    BN_clear_free(phony_private_integer);
    EC_KEY_free(ec_key);
    return result;
}

bool writeout_certificate_file(X509 *x509, BIO *bio_err, const char *path) {
    FILE * fp;
    if (! (fp = fopen(path, "wb"))) {
        BIO_printf(bio_err, "ERROR: Error in opening output certificate file.");
        return false;
    }

    if ( PEM_write_X509(fp, x509) == false ) {
        BIO_printf(bio_err, "ERROR: Error in writing output certificate file.\n");
        return false;
    }

    if (fclose(fp)) {
        BIO_printf(bio_err, "ERROR: Error in closing output certificate file.\n");
        return false;
    }

    return true;
}
