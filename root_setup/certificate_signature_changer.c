
#include <stdio.h>
#include <stdlib.h>

#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

typedef     char    bool;
#define     true            1
#define     false           0
static const char *ENGINE_ID                    =       "Mozecengine";

bool process_args(int argc, char *argv[], char **input_cert_path, char **input_pukey_path, char **output_cert_path);
bool setup();
bool load_input_cert(X509 **input_cert, const char *input_cert_path);
bool load_public_key(EVP_PKEY **pukey, const char *input_pukey_path);
bool make_changes(X509 *cert, EVP_PKEY *pukey);
bool write_out_the_result(X509 *cert, const char *output_cert_path);
void tear_down(X509 *cert, EVP_PKEY *pukey);
int main(int argc, char *argv[]) {
    char *input_cert_path = NULL, *input_pukey_path = NULL, *output_cert_path = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pukey = NULL;

    setup();
    if(!process_args(argc, argv, &input_cert_path, &input_pukey_path, &output_cert_path))
        return 1;
    if(!load_input_cert(&cert, input_cert_path))
        return 2;
    if(!load_public_key(&pukey, input_pukey_path))
        return 3;
    if(!make_changes(cert, pukey)) {
        tear_down(cert, pukey);
        return 4;
    }
    if(!write_out_the_result(cert, output_cert_path)) {
        tear_down(cert, pukey);
        return 5;
    }
    tear_down(cert, pukey);
    printf("success!\n");
    return 0;
}

bool process_args(int argc, char *argv[], char **input_cert_path, char **input_pukey_path, char **output_cert_path) {
    if(argc < 4) {
        fprintf(stderr, "correct usage: ./exec.out input_cert_path input_pukey_path output_cert_path\n");
        *input_cert_path = *output_cert_path = NULL;
        return false;
    }
    *input_cert_path = argv[1];
    *input_pukey_path = argv[2];
    *output_cert_path = argv[3];
    printf("INFO: changing the certificate %s and writing the result to %s .\n", *input_cert_path, *output_cert_path);
    return true;
}

bool setup() {
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    ERR_load_crypto_strings();

    ENGINE_load_dynamic();
    ENGINE *engine = ENGINE_by_id(ENGINE_ID);
    if(!engine) {
        fprintf(stderr, "could not load engine\n");
        return false;
    }
    return true;
}

bool load_input_cert(X509 **input_cert, const char *input_cert_path) {
    FILE *f = fopen(input_cert_path, "r");
    if(!f) {
        fprintf(stderr, "could not read the input certificate file.\n");
        return false;
    }
    *input_cert = PEM_read_X509(f, 0, 0, 0);
    if(fclose(f)) {
        fprintf(stderr, "could not close the input certificate file.\n");
        if(*input_cert)
            X509_free(*input_cert);
    }
    else if(!(*input_cert_path))
        fprintf(stderr, "could not read the input certificate file.\n");
    else
        return true;
    return false;
}

bool load_public_key(EVP_PKEY **pukey, const char *input_pukey_path) {
    FILE *f = fopen(input_pukey_path, "r");
    if(!f) {
        fprintf(stderr, "could not read the input public key file.\n");
        return false;
    }
    *pukey = PEM_read_PUBKEY(f, 0, 0, 0);
    if(fclose(f)) {
        fprintf(stderr, "could not close the input public key file.\n");
        if(*pukey)
            EVP_PKEY_free(*pukey);
    }
    else if(!(*pukey))
        fprintf(stderr, "could not read the input public key file.\n");
    else
        return true;
    return false;
}

bool make_changes(X509 *cert, EVP_PKEY *pukey) {
    if(!X509_set_pubkey(cert,pukey))
        fprintf(stderr, "could not set the public key of the certificate\n");
    else if (!X509_sign(cert,NULL,EVP_sha256()))
        fprintf(stderr, "could not sign the certificate\n");
    else
        return true;
    return false;
}

bool write_out_the_result(X509 *cert, const char *output_cert_path) {
    FILE *f = fopen(output_cert_path, "w");
    if(!f)
        fprintf(stderr, "could not open the output certificate file.\n");
    else if(!PEM_write_X509(f, cert))
        fprintf(stderr, "could not write out the output certificate.\n");
    else if(fclose(f))
        fprintf(stderr, "could not close the output certificate file.\n");
    else
        return true;
    return false;
}

void tear_down(X509 *cert, EVP_PKEY *pukey) {
    if(cert)
        X509_free(cert);
    if(pukey)
        EVP_PKEY_free(pukey);
}
