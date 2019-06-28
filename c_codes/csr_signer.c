#include <stdio.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>

#include "commons.h"

typedef struct _params {
    char *CSR_PATH;
    char *EXT_FILE_PATH;

    char *OUTPUT_CERT_PATH;
    char *START_DATE_ASN1;
    char *END_DATE_ASN1;
    unsigned long SERIAL;
    bool OUTPUT_X509_V3;

    char *CA_CERT_PATH;

    char *ECENGINE_PATH;
    bool LOAD_ECENGINE;
    bool DEBUG;
} parameters;

int main(int argc, char *argv[]);
bool load_parameters(parameters *p, const char *path);
bool setup(BIO **bio_err, parameters *p);
bool make_certificate(parameters *p, BIO *bio_err);
    bool load_conf(CONF **conf, char **section, BIO *bio_err, const char *path);
    bool init_certificate_from_csr_and_root(X509 **new_crt, X509_REQ *csr, X509 *root_crt, BIO *bio_err, parameters *p);
    bool add_non_csr_data_to_certificate(X509 *crt, X509* root_crt, CONF *extensions,
        char *extensions_section, parameters *p, BIO *bio_err);
        bool apply_configuration(X509 *x, X509 *root_crt, CONF *conf, char *section);
    bool load_engine_if_needed(parameters *p, BIO *bio_err);
    bool forge_sign(X509 *new_crt, X509 *root_crt, BIO *bio_err);
void debug_print_parameters(parameters *p);

int main(int argc, char *argv[]) {
    BIO *bio_err = NULL;
    parameters params;

    if (argc < 2) {
        fprintf(stderr, "ERROR: The first main argument must be parameters file path. Not enough parameters. Aborting...\n");
        return 1;
    }

    if(!load_parameters(&params, argv[1])) {
        fprintf(stderr, "ERROR: Could not load parameters from file %s. Aborting ...\n", argv[1]);
        return 1;
    }

    if(params.DEBUG)
        debug_print_parameters(&params);

    if(!setup(&bio_err, &params)) {
        fprintf(stderr, "ERROR: Could not setup Openssl. Aborting ...\n");
        return 1;
    }

    if(make_certificate(&params, bio_err) == false) {
        BIO_printf(bio_err, "ERROR: The operation failed due to previous errors.\n");
        return 1;
    }

    return 0;
}

bool load_parameters(parameters *p, const char *path) {
    size_t limit = 0;
    char *temp_buffer=0;
    FILE *f = fopen(path, "r");
    for(char *c = (char*) p; c < sizeof(*p) + (char*)p; c++)
        *c = 0;
    if(!f)
        return false;

    if(getline_trim(&(p->CSR_PATH), &limit, f) <= 0) return false;
    if(getline_trim(&(p->EXT_FILE_PATH), &limit, f) <= 0) return false;
    if(getline_trim(&(p->OUTPUT_CERT_PATH), &limit, f) <= 0) return false;
    if(getline_trim(&(p->START_DATE_ASN1), &limit, f) <= 0) return false;
    if(getline_trim(&(p->END_DATE_ASN1), &limit, f) <= 0) return false;

    if(fscanf(f, "0x%lx", &(p->SERIAL)) < 1)
        return false;
    if(!consume_line_till_end(f)) return false;

    if(!read_boolean_pointer(f, &(p->OUTPUT_X509_V3))) return false;
    if(getline_trim(&(p->CA_CERT_PATH), &limit, f) <= 0) return false;
    if(getline_trim(&(p->ECENGINE_PATH), &limit, f) <= 0) return false;
    if(!read_boolean_pointer(f, &(p->LOAD_ECENGINE))) return false;
    if(!read_boolean_pointer(f, &(p->DEBUG))) return false;

    return true;
}

bool setup(BIO **bio_err, parameters *p) {
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    if (! load_engine_if_needed(p, *bio_err)) {
        return false;
    } 
    return true;
}

bool make_certificate(parameters *p, BIO *bio_err) {
    X509_REQ *csr = NULL;
    X509 *root_crt = NULL, *new_crt = NULL;
    CONF *extensions = NULL;
    char *extensions_section = NULL;

    if (load_csr(&csr, bio_err, p->CSR_PATH) == false)
        return false;
    if (load_crt(&root_crt, bio_err, p->CA_CERT_PATH) == false)
        return false;
    if (load_conf(&extensions, &extensions_section, bio_err, p->EXT_FILE_PATH) == false)
        return false;
    if (init_certificate_from_csr_and_root(&new_crt, csr, root_crt, bio_err, p) == false) {
        BIO_printf(bio_err, "ERROR: Could not init the new certificate from csr and root certificate.\n");
        return false;
    }
    if (add_non_csr_data_to_certificate(new_crt, root_crt, extensions, extensions_section, p, bio_err) == false) {
        BIO_printf(bio_err, "ERROR: Could add extensions to the new certificate.\n");
        return false;
    }
    if (forge_sign(new_crt, root_crt, bio_err) == false) {
        BIO_printf(bio_err, "ERROR: Could not sign the new certificate.\n");
        return false;
    }

    return writeout_certificate_file(new_crt, bio_err, p->OUTPUT_CERT_PATH);
}

bool load_conf(CONF **conf, char **section, BIO *bio_err, const char *path) {
    long error_line = -1;
    X509V3_CTX ctx;
    CONF *extconf = NCONF_new(NULL);
    char *extsect = NULL;
    if (!NCONF_load(extconf, path, &error_line)) {
        if (error_line <= 0)
            BIO_printf(bio_err, "ERROR: error loading the config file '%s'\n", path);
        else
            BIO_printf(bio_err, "ERROR: error on line %ld of config file '%s'\n", error_line, path);
        return false;
    }
    extsect = NCONF_get_string(extconf, "default", "extensions");
    if (!extsect) {
        ERR_clear_error();
        extsect = "default";
    }
    X509V3_set_ctx_test(&ctx);
    X509V3_set_nconf(&ctx, extconf);
    if (!X509V3_EXT_add_nconf(extconf, &ctx, extsect, NULL)) {
        BIO_printf(bio_err, "ERROR: error loading extension section %s\n", extsect);
        ERR_print_errors(bio_err);
        return false;
    }

    *conf = extconf;
    *section = extsect;
    return true;
}

bool init_certificate_from_csr_and_root(X509 **new_crt, X509_REQ *csr, X509 *root_crt, BIO *bio_err, parameters *p) {
    X509 *crt = NULL;
    X509_NAME *temp_name = NULL;
    EVP_PKEY *csr_pubkey = NULL;

    crt = X509_new();
    if (!crt) {
        BIO_printf(bio_err, "ERROR: Error in creating new X509 object\n");
        return false;
    }

    temp_name = X509_REQ_get_subject_name(csr);
    if(!temp_name) {
        BIO_printf(bio_err, "ERROR: Error getting subject from cert request.\n");
        X509_free(crt);
        return false;
    }
    if (X509_set_subject_name(crt, temp_name) != 1) {
        BIO_printf(bio_err, "ERROR: Error setting subject name of certificate.\n");
        X509_free(crt);
        return false;
    }
    temp_name = X509_get_subject_name(root_crt);
    if(!temp_name) {
        BIO_printf(bio_err, "ERROR: Error getting subject from CA certificate.\n");
        X509_free(crt);
        return false;
    }
    if (X509_set_issuer_name(crt, temp_name) != 1) {
        BIO_printf(bio_err, "ERROR: Error setting issuer name of certificate.\n");
        X509_free(crt);
        return false;
    }

    csr_pubkey=X509_REQ_get_pubkey(csr);
    if (!csr_pubkey) {
        BIO_printf(bio_err, "ERROR: Error unpacking public key from request.\n");
        X509_free(crt);
        return false;
    }

    if (!(p->LOAD_ECENGINE) && X509_REQ_verify(csr, csr_pubkey) != 1) {
        BIO_printf(bio_err, "ERROR: Error verifying signature on request.\n");
        X509_free(crt);
        return false;
    }

    if (X509_set_pubkey(crt, csr_pubkey) != 1) {
        BIO_printf(bio_err, "ERROR: Error setting public key of certificate.\n");
        X509_free(crt);
        return false;
    }

    *new_crt = crt;
    return true;
}

bool add_non_csr_data_to_certificate(X509 *crt, X509* root_crt, CONF *extensions,
        char *extensions_section, parameters *p, BIO *bio_err) {

    if ( 1 != X509_set_version(crt, p->OUTPUT_X509_V3 ? 3 : 2) ) {
        BIO_printf(bio_err, "ERROR: Error setting certificate version\n");
        return false;
    }
    ASN1_INTEGER_set(X509_get_serialNumber(crt),p->SERIAL);
    if (! ASN1_TIME_set_string(X509_get_notBefore(crt), p->START_DATE_ASN1)) {
        BIO_printf(bio_err, "ERROR: Error in setting the start date: %s\n", p->START_DATE_ASN1);
        return false;
    }
    if (! ASN1_TIME_set_string(X509_get_notAfter(crt), p->END_DATE_ASN1)) {
        BIO_printf(bio_err, "ERROR: Error in setting the end date: %s\n", p->END_DATE_ASN1);
        return false;
    }
    if(! apply_configuration(crt, root_crt, extensions, extensions_section)) {
        BIO_printf(bio_err, "ERROR: Error adding extensions to the new certificate.\n");
        return false;
    }
    return true;
}

bool apply_configuration(X509 *x, X509 *root_crt, CONF *conf, char *section) {
    if (!conf || !section)
        return false;

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, root_crt, x, NULL, NULL, 0);
    X509V3_set_nconf(&ctx, conf);
    if (!X509V3_EXT_add_nconf(conf, &ctx, section, x))
        return false;
    else
        return true;
}

bool load_engine_if_needed(parameters *p, BIO *bio_err) {
    if(p->LOAD_ECENGINE) {
        ENGINE_load_dynamic();
        ENGINE *e = ENGINE_by_id(p->ECENGINE_PATH);
        if( e == NULL ) {
            BIO_printf(bio_err, "ERROR: Could not find the engine: %s\n", p->ECENGINE_PATH);
            return false;
        }
	    if(!ENGINE_set_default_EC(e)) {
            BIO_printf(bio_err, "ERROR: Could not register the engine for ECDSA operation.\n");
            return false;
        }
    }
    return true;
}

bool forge_sign(X509 *new_crt, X509 *root_crt, BIO *bio_err) {
    EVP_PKEY *forged_root_key = NULL, *root_pubkey = NULL;
    root_pubkey = X509_get_pubkey(root_crt);
    if (!root_pubkey) {
        BIO_printf(bio_err, "ERROR: Error unpacking public key from root certificate.\n");
        return false;
    }
    forged_root_key = forge_dummy_private_key_from_public(root_pubkey);
    if(!forged_root_key) {
        BIO_printf(bio_err,
                "ERROR: creating dummy private key (to circumvent openssl error checkings) from the public key.\n");
        return false;
    }

    if (X509_sign(new_crt,forged_root_key,EVP_sha256()) == false) {
        BIO_printf(bio_err, "ERROR: Error in signing the certificate.\n");
        return false;
    }
    return true;
}

void debug_print_parameters(parameters *p) {
    if(p) {
        printf("DEBUG: parameters:\n");

        printf("DEBUG: CSR_PATH=%s\n", p->CSR_PATH);
        printf("DEBUG: EXT_FILE_PATH=%s\n", p->EXT_FILE_PATH);

        printf("DEBUG: OUTPUT_CERT_PATH=%s\n", p->OUTPUT_CERT_PATH);
        printf("DEBUG: START_DATE_ASN1=%s\n", p->START_DATE_ASN1);
        printf("DEBUG: END_DATE_ASN1=%s\n", p->END_DATE_ASN1);
        printf("DEBUG: SERIAL=0x%lx\n", p->SERIAL);
        printf("DEBUG: OUTPUT_X509_V3=%i\n", p->OUTPUT_X509_V3);

        printf("DEBUG: CA_CERT_PATH=%s\n", p->CA_CERT_PATH);

        printf("DEBUG: ECENGINE_PATH=%s\n", p->ECENGINE_PATH);
        printf("DEBUG: LOAD_ECENGINE=%i\n", p->LOAD_ECENGINE);
        printf("DEBUG: DEBUG=%i\n", p->DEBUG);
        printf("\n");
    } else {
            printf("DEBUG: NULL");
    }
}
