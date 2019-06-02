#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>


typedef     char    bool;
#define     true            1
#define     false           0
#ifndef     NULL
#define     NULL            0
#endif

const char *PARAMETERS_FILE_PATH = ".c_parameters.txt";

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
    char *ECENGINE_LOCATION;
    char *PUKEY_PATH;
    char *OUTPUT_CERT_LOCATION;
    bool LOAD_ECENGINE;
    bool DEBUG;
} parameters;

int main(int argc, char *argv[]);
bool load_parameters(parameters *p);
    ssize_t getline_trim(char **lineptr, size_t *n, FILE *f);
    bool read_boolean_pointer(FILE *f, bool *result);
    bool consume_line_till_end(FILE *f);
bool setup(BIO **bio_err, parameters *p);
bool make_certificate(X509 **x509, EVP_PKEY **pukey, BIO *bio_err, parameters *p);
    bool load_public_key(EVP_PKEY **pukey, BIO *bio_err, parameters *p);
    bool mkcert(X509 **x509p, EVP_PKEY *pukey, BIO *bio_err, parameters *p);
        bool add_subject_line(X509 *cert, parameters *p, BIO *bio_err);
        bool add_extensions(X509 *cert, BIO *bio_err);
        bool add_ext(X509 *cert, int nid, char *value);
        EVP_PKEY *forge_dummy_private_key_from_public(EVP_PKEY *pukey);
    bool writeout_certificate_file(X509 *x509, BIO *bio_err, parameters *p);
void teardown(X509 *x509, EVP_PKEY *pukey, BIO *bio_err, parameters *p);
    void free_parameters(parameters *p);
void debug_print_parameters(parameters *p);

int main(int argc, char *argv[]) {
    BIO *bio_err;
    X509 *x509=NULL;
    EVP_PKEY *pukey=NULL;
    parameters params;

    if(!load_parameters(&params)) {
        fprintf(stderr, "ERROR: Could not load parameters from file %s. Aborting ...\n", PARAMETERS_FILE_PATH);
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

bool load_parameters(parameters *p) {
    size_t limit = 0;
    char *temp_buffer=0;
    FILE *f = fopen(PARAMETERS_FILE_PATH, "r");
    for(char *c = (char*) p; c < sizeof(*p) + (char*)p; c++)
        *c = 0;
    if(!f)
        return false;

    if(fscanf(f, "0x%lux", &(p->SERIAL)) < 1)
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
    if(getline_trim(&(p->ECENGINE_LOCATION), &limit, f) <= 0) return false;
    if(getline_trim(&(p->PUKEY_PATH), &limit, f) <= 0) return false;
    if(getline_trim(&(p->OUTPUT_CERT_LOCATION), &limit, f) <= 0) return false;
    if(!read_boolean_pointer(f, &(p->LOAD_ECENGINE))) return false;
    if(!read_boolean_pointer(f, &(p->DEBUG))) return false;

    return true;
}

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

bool setup(BIO **bio_err, parameters *p) {
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    if(p->LOAD_ECENGINE) {
        ENGINE_load_dynamic();
        ENGINE *e = ENGINE_by_id(p->ECENGINE_LOCATION);
        if( e == NULL ) {
            BIO_printf(*bio_err, "ERROR: Could not find the engine: %s\n", p->ECENGINE_LOCATION);
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
    if (load_public_key(pukey, bio_err, p) == false)
        return false;

    if (mkcert(x509, *pukey, bio_err, p) == false) {
        BIO_printf(bio_err, "ERROR: Could not create the certificate\n");
        return false;
    }

    return writeout_certificate_file(*x509, bio_err, p);
}

bool load_public_key(EVP_PKEY **pukey, BIO *bio_err, parameters *p) {
    EVP_PKEY *pk;
    FILE    *fp;

    if (! (pk=EVP_PKEY_new())) {
        BIO_printf(bio_err, "ERROR: Error in creating private key data structure.\n");
        return false;
    }
    if (! (fp = fopen (p->PUKEY_PATH, "r"))) {
        BIO_printf(bio_err, "ERROR: Error reading CA private key file.\n");
        return false;
    }
    if (! (pk = PEM_read_PUBKEY( fp, NULL, NULL, NULL))) {
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

bool mkcert(X509 **x509p, EVP_PKEY *pukey, BIO *bio_err, parameters *p) {
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

bool writeout_certificate_file(X509 *x509, BIO *bio_err, parameters *p) {
    FILE * fp;
    if (! (fp = fopen(p->OUTPUT_CERT_LOCATION, "wb"))) {
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
    free(p->ECENGINE_LOCATION);
    free(p->PUKEY_PATH);
    free(p->OUTPUT_CERT_LOCATION);
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
        printf("DEBUG: SERIAL=0x%lu\n", p->SERIAL);
        printf("DEBUG: OUTPUT_X509_V3=%i\n", p->OUTPUT_X509_V3);
        printf("DEBUG: ECENGINE_LOCATION=%s\n", p->ECENGINE_LOCATION);
        printf("DEBUG: PUKEY_PATH=%s\n", p->PUKEY_PATH);
        printf("DEBUG: OUTPUT_CERT_LOCATION=%s\n", p->OUTPUT_CERT_LOCATION);
        printf("DEBUG: LOAD_ECENGINE=%i\n", p->LOAD_ECENGINE);
        printf("DEBUG: DEBUG=%i\n", p->DEBUG);
        printf("\n");
    } else {
            printf("DEBUG: NULL");
        }
    }
