#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>
#include <openssl/evp.h>

#include "util.h"

typedef struct _params {
    char *SBJ_C;
    char *SBJ_ST;
    char *SBJ_L;
    char *SBJ_O;
    char *SBJ_OU;
    char *SBJ_CN;
    char *SBJ_EMAIL;
    char *START_DATE_ASN1;
    char *END_DATE_ASN1;
    unsigned long SERIAL;

    bool OUTPUT_X509_V3;
    char *ECENGINE_PATH;
    char *CA_PUBKEY_PATH;
    char *OUTPUT_CERT_PATH;
    bool LOAD_ECENGINE;
    bool DEBUG;
} parameters;

int main(int argc, char *argv[]);
bool load_parameters(parameters *p, const char *path);
bool setup(BIO **bio_err, parameters *p);
bool make_certificate(X509 **x509, EVP_PKEY **pukey, BIO *bio_err, parameters *p);
    bool build_certificate_data_structure(X509 **x509p, EVP_PKEY *pukey, BIO *bio_err, parameters *p);
        bool add_subject_line(X509 *cert, parameters *p, BIO *bio_err);
        bool add_extensions(X509 *cert, BIO *bio_err);
        bool add_ext(X509 *cert, int nid, char *value);
void teardown(X509 *x509, EVP_PKEY *pukey, BIO *bio_err, parameters *p);
    void free_parameters(parameters *p);
void debug_print_parameters(parameters *p);

int main(int argc, char *argv[]) {
    BIO *bio_err;
    X509 *x509=NULL;
    EVP_PKEY *pukey=NULL;
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
    bool result = make_certificate(&x509, &pukey, bio_err, &params);
    if(result == false) {
        BIO_printf(bio_err, "ERROR: The operation failed due to previous errors\n");
        teardown(x509, pukey, bio_err, &params);
        return 1;
    }
    teardown(x509, pukey, bio_err, &params);

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

    if(fscanf(f, "0x%lx", &(p->SERIAL)) < 1)
        return false;
    if(!consume_line_till_end(f)) return false;

    if(getline_trim(&(p->START_DATE_ASN1), &limit, f) <= 0) return false;
    if(getline_trim(&(p->END_DATE_ASN1), &limit, f) <= 0) return false;

    if(!read_boolean_pointer(f, &(p->OUTPUT_X509_V3))) return false;
    if(getline_trim(&(p->SBJ_C), &limit, f) <= 0) return false;
    if(getline_trim(&(p->SBJ_ST), &limit, f) <= 0) return false;
    if(getline_trim(&(p->SBJ_L), &limit, f) <= 0) return false;
    if(getline_trim(&(p->SBJ_O), &limit, f) <= 0) return false;
    if(getline_trim(&(p->SBJ_OU), &limit, f) <= 0) return false;
    if(getline_trim(&(p->SBJ_CN), &limit, f) <= 0) return false;
    if(getline_trim(&(p->SBJ_EMAIL), &limit, f) <= 0) return false;
    if(getline_trim(&(p->ECENGINE_PATH), &limit, f) <= 0) return false;
    if(getline_trim(&(p->CA_PUBKEY_PATH), &limit, f) <= 0) return false;
    if(getline_trim(&(p->OUTPUT_CERT_PATH), &limit, f) <= 0) return false;
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
    if(p->LOAD_ECENGINE) {
        ENGINE_load_dynamic();
        ENGINE *e = ENGINE_by_id(p->ECENGINE_PATH);
        if( e == NULL ) {
            BIO_printf(*bio_err, "ERROR: Could not find the engine: %s\n", p->ECENGINE_PATH);
            return false;
        }
	    if(!ENGINE_set_default_ECDSA(e)) {
            BIO_printf(*bio_err, "ERROR: Could not register the engine for ECDSA operation.\n");
            return false;
        }
    }
    return true;
}

bool make_certificate(X509 **x509, EVP_PKEY **pukey, BIO *bio_err, parameters *p) {
    if (load_public_key(pukey, bio_err, p->CA_PUBKEY_PATH) == false)
        return false;

    if (build_certificate_data_structure(x509, *pukey, bio_err, p) == false) {
        BIO_printf(bio_err, "ERROR: Could not create the certificate\n");
        return false;
    }

    return writeout_certificate_file(*x509, bio_err, p->OUTPUT_CERT_PATH);
}

bool build_certificate_data_structure(X509 **x509p, EVP_PKEY *pukey, BIO *bio_err, parameters *p) {
    X509 *x;

    if ((x=X509_new()) == NULL) {
        BIO_printf(bio_err, "ERROR: Error in creating X509 data structure.\n");
        return false;
    }

    if(p->OUTPUT_X509_V3)
        X509_set_version(x,3);
    ASN1_INTEGER_set(X509_get_serialNumber(x),p->SERIAL);
    if (! ASN1_TIME_set_string(X509_get_notBefore(x), p->START_DATE_ASN1)) {
        BIO_printf(bio_err, "ERROR: Error in setting the start date: %s\n", p->START_DATE_ASN1);
        return false;
    }
    if (! ASN1_TIME_set_string(X509_get_notAfter(x), p->END_DATE_ASN1)) {
        BIO_printf(bio_err, "ERROR: Error in setting the end date: %s\n", p->END_DATE_ASN1);
        return false;
    }

    X509_set_pubkey(x,pukey);
    if(!add_subject_line(x, p, bio_err)) {
        BIO_printf(bio_err, "ERROR: Error in parsing the subject line.\n");
        return false;
    }
    //self sign the certificate
    X509_set_issuer_name(x,X509_get_subject_name(x));

    if(!add_extensions(x, bio_err)) {
        BIO_printf(bio_err, "ERROR: Error in adding extensions to the certificate.\n");
        return false;
    }

    EVP_PKEY *forged = forge_dummy_private_key_from_public(pukey);
    if(!forged) {
        BIO_printf(bio_err,
                "ERROR: creating dummy private key (to circumvent openssl error checkings) from the public key.\n");
        return false;
    }
    if (X509_sign(x,forged,EVP_sha256()) == false) {
        BIO_printf(bio_err, "ERROR: Error in signing the certificate.\n");
        EVP_PKEY_free(forged);
        return false;
    }

    EVP_PKEY_free(forged);
    *x509p=x;
    return true;
}

bool add_subject_line(X509 *cert, parameters *p, BIO *bio_err) {

	X509_NAME *name = X509_get_subject_name(cert);
	if(!X509_NAME_add_entry_by_txt(name,"C", MBSTRING_ASC,  (const unsigned char *)(p->SBJ_C),-1,-1,0)) return false;
	if(!X509_NAME_add_entry_by_txt(name,"ST", MBSTRING_ASC, (const unsigned char *)(p->SBJ_ST),-1,-1,0)) return false;
	if(!X509_NAME_add_entry_by_txt(name,"L", MBSTRING_ASC,  (const unsigned char *)(p->SBJ_L),-1,-1,0)) return false;
	if(!X509_NAME_add_entry_by_txt(name,"O", MBSTRING_ASC,  (const unsigned char *)(p->SBJ_O),-1,-1,0)) return false;
	if(!X509_NAME_add_entry_by_txt(name,"OU", MBSTRING_ASC, (const unsigned char *)(p->SBJ_OU),-1,-1,0)) return false;
	if(!X509_NAME_add_entry_by_txt(name,"CN", MBSTRING_ASC, (const unsigned char *)(p->SBJ_CN),-1,-1,0)) return false;
	if(!X509_NAME_add_entry_by_txt(name,"emailAddress", MBSTRING_ASC, (const unsigned char *)(p->SBJ_EMAIL),-1,-1,0)) return false;
    return true;
}

bool add_extensions(X509 *cert, BIO *bio_err) {
    if(false) {}
    else if(! add_ext(cert, NID_subject_key_identifier, (char *)"hash"))
        BIO_printf(bio_err, "ERROR: Error in adding subject key identifier extension the certificate.\n");
    else if(! add_ext(cert, NID_authority_key_identifier, (char *)"keyid:always"))
        BIO_printf(bio_err, "ERROR: Error in adding authority key identifier extension the certificate.\n");
    else if(! add_ext(cert, NID_basic_constraints, (char *)"critical,CA:TRUE"))
        BIO_printf(bio_err, "ERROR: Error in adding basic constraints extension the certificate.\n");
    else
        return true;

    return false;
}

/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */
bool add_ext(X509 *cert, int nid, char *value) {
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /* Issuer and subject certs: both the target since it is self signed,
     * no request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert,ex,-1);
    X509_EXTENSION_free(ex);
    return 1;
}

void teardown(X509 *x509, EVP_PKEY *pukey, BIO *bio_err, parameters *p) {
    X509_free(x509);
    EVP_PKEY_free(pukey);

    ENGINE_cleanup();
    CRYPTO_cleanup_all_ex_data();

    CRYPTO_mem_leaks(bio_err);
    BIO_free(bio_err);
    free_parameters(p);
}

void free_parameters(parameters *p) {
    free(p->SBJ_C);
    free(p->SBJ_ST);
    free(p->SBJ_L);
    free(p->SBJ_O);
    free(p->SBJ_OU);
    free(p->SBJ_CN);
    free(p->SBJ_EMAIL);
    free(p->START_DATE_ASN1);
    free(p->END_DATE_ASN1);
    free(p->ECENGINE_PATH);
    free(p->CA_PUBKEY_PATH);
    free(p->OUTPUT_CERT_PATH);
}

void debug_print_parameters(parameters *p) {
    if(p) {
        printf("DEBUG: parameters:\n");
        printf("DEBUG: SBJ_C=%s\n", p->SBJ_C);
        printf("DEBUG: SBJ_ST=%s\n", p->SBJ_ST);
        printf("DEBUG: SBJ_L=%s\n", p->SBJ_L);
        printf("DEBUG: SBJ_O=%s\n", p->SBJ_O);
        printf("DEBUG: SBJ_OU=%s\n", p->SBJ_OU);
        printf("DEBUG: SBJ_CN=%s\n", p->SBJ_CN);
        printf("DEBUG: SBJ_EMAIL=%s\n", p->SBJ_EMAIL);
        printf("DEBUG: START_DATE_ASN1=%s\n", p->START_DATE_ASN1);
        printf("DEBUG: END_DATE_ASN1=%s\n", p->END_DATE_ASN1);
        printf("DEBUG: SERIAL=0x%lx\n", p->SERIAL);
        printf("DEBUG: OUTPUT_X509_V3=%i\n", p->OUTPUT_X509_V3);
        printf("DEBUG: ECENGINE_PATH=%s\n", p->ECENGINE_PATH);
        printf("DEBUG: CA_PUBKEY_PATH=%s\n", p->CA_PUBKEY_PATH);
        printf("DEBUG: OUTPUT_CERT_PATH=%s\n", p->OUTPUT_CERT_PATH);
        printf("DEBUG: LOAD_ECENGINE=%i\n", p->LOAD_ECENGINE);
        printf("DEBUG: DEBUG=%i\n", p->DEBUG);
        printf("\n");
    } else {
            printf("DEBUG: NULL");
    }
}
