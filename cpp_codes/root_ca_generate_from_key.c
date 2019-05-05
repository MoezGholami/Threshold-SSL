#include "constants.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>

int main(int argc, char *argv[]);
void setup(BIO **bio_err);
bool make_certificate(X509 **x509, EVP_PKEY **pkey, BIO *bio_err);
    bool load_private_key(EVP_PKEY **pkey, BIO *bio_err);
    bool mkcert(X509 **x509p, EVP_PKEY *pk, BIO *bio_err, unsigned long serial, int days, const char *subject);
        bool parse_and_add_subject_line(X509 *cert, const char *subject, BIO *bio_err);
            X509_NAME *parse_name(const char *cp, long chtype, int canmulti, BIO *bio_err);
        bool add_extensions(X509 *cert, BIO *bio_err);
        bool add_ext(X509 *cert, int nid, char *value);
    bool writeout_certificate_file(X509 *x509, BIO *bio_err);
void teardown(X509 *x509, EVP_PKEY *pkey, BIO *bio_err);

int main(int argc, char *argv[]) {
    BIO *bio_err;
    X509 *x509=NULL;
    EVP_PKEY *pkey=NULL;

    setup(&bio_err);
    bool result = make_certificate(&x509, &pkey, bio_err);
    if(result == false) {
        BIO_printf(bio_err, "The operation failed due to previous errors\n");
        teardown(x509, pkey, bio_err);
        return 1;
    }
    teardown(x509, pkey, bio_err);

    return 0;
}

void setup(BIO **bio_err) {
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
}

bool make_certificate(X509 **x509, EVP_PKEY **pkey, BIO *bio_err) {
    if (load_private_key(pkey, bio_err) == false)
        return false;

    if (mkcert(x509, *pkey, bio_err, SERIAL, DAYS, SUBJECT_LINE) == false) {
        BIO_printf(bio_err, "Could not create the certificate\n");
        return false;
    }

    return writeout_certificate_file(*x509, bio_err);
}

bool load_private_key(EVP_PKEY **pkey, BIO *bio_err) {
    EVP_PKEY *pk;
    FILE    *fp;

    if (! (pk=EVP_PKEY_new())) {
        BIO_printf(bio_err, "Error in creating private key data structure.\n");
        return false;
    }
    if (! (fp = fopen (ROOT_KEY_FILE, "r"))) {
        BIO_printf(bio_err, "Error reading CA private key file.\n");
        return false;
    }
    if (! (pk = PEM_read_PrivateKey( fp, NULL, NULL, ROOT_KEY_PASS))) {
        BIO_printf(bio_err, "Error importing key content from file.\n");
        return false;
    }
    if (fclose(fp)) {
        BIO_printf(bio_err, "Error in closing key content file.\n");
        return false;
    }

    *pkey = pk;
    return true;
}

bool mkcert(X509 **x509p, EVP_PKEY *pk, BIO *bio_err, unsigned long serial, int days, const char *subject) {
    X509 *x;

    if ((x=X509_new()) == NULL) {
        BIO_printf(bio_err, "Error in creating X509 data structure.\n");
        return false;
    }

    X509_set_version(x,3);
    ASN1_INTEGER_set(X509_get_serialNumber(x),serial);
    X509_gmtime_adj(X509_get_notBefore(x),0);
    X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
    X509_set_pubkey(x,pk);
    if(!parse_and_add_subject_line(x, subject, bio_err)) {
        BIO_printf(bio_err, "Error in parsing the subject line.\n");
        return false;
    }
    //self sign the certificate
    X509_set_issuer_name(x,X509_get_subject_name(x));

    if(!add_extensions(x, bio_err)) {
        BIO_printf(bio_err, "Error in adding extensions to the certificate.\n");
        return false;
    }

    if (X509_sign(x,pk,EVP_sha256()) == false) {
        BIO_printf(bio_err, "Error in signing the certificate.\n");
        return false;
    }

    *x509p=x;
    return true;
}

bool parse_and_add_subject_line(X509 *cert, const char *subject, BIO *bio_err) {
    X509_NAME *name = parse_name(subject, MBSTRING_ASC, 1, bio_err);
    if(! name) {
        BIO_printf(bio_err, "Error in parsing subject name.\n");
        return false;
    }
    if(! X509_set_subject_name(cert, name) ) {
        BIO_printf(bio_err, "Error in setting subject name.\n");
        return false;
    }
    X509_NAME_free(name);
    return true;
}

bool add_extensions(X509 *cert, BIO *bio_err) {
    if(false) {}
    else if(! add_ext(cert, NID_subject_key_identifier, (char *)"hash"))
        BIO_printf(bio_err, "Error in adding subject key identifier extension the certificate.\n");
    else if(! add_ext(cert, NID_authority_key_identifier, (char *)"keyid:always"))
        BIO_printf(bio_err, "Error in adding authority key identifier extension the certificate.\n");
    else if(! add_ext(cert, NID_basic_constraints, (char *)"critical,CA:TRUE"))
        BIO_printf(bio_err, "Error in adding basic constraints extension the certificate.\n");
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

bool writeout_certificate_file(X509 *x509, BIO *bio_err) {
    FILE * fp;
    if (! (fp = fopen(CERT_OUTPUT_FILE, "wb"))) {
        BIO_printf(bio_err, "Error in opening output certificate file.");
        return false;
    }

    if ( PEM_write_X509(fp, x509) == false ) {
        BIO_printf(bio_err, "Error in writing output certificate file.\n");
        return false;
    }

    if (fclose(fp)) {
        BIO_printf(bio_err, "Error in closing output certificate file.\n");
        return false;
    }

    return true;
}

void teardown(X509 *x509, EVP_PKEY *pkey, BIO *bio_err) {
    X509_free(x509);
    EVP_PKEY_free(pkey);

    ENGINE_cleanup();
    CRYPTO_cleanup_all_ex_data();

    CRYPTO_mem_leaks(bio_err);
    BIO_free(bio_err);
}

// brought (copy + minor modification) from openssl source code
X509_NAME *parse_name(const char *cp, long chtype, int canmulti, BIO *bio_err) {
    int nextismulti = 0;
    char *work;
    X509_NAME *n;

    if (*cp++ != '/') {
        BIO_printf(bio_err,
                   "name is expected to be in the format "
                   "/type0=value0/type1=value1/type2=... where characters may "
                   "be escaped by \\. This name is not in that format: '%s'\n",
                   --cp);
        return NULL;
    }

    n = X509_NAME_new();
    if (n == NULL)
        return NULL;
    work = OPENSSL_strdup(cp);
    if (work == NULL) {
        BIO_printf(bio_err, "Error copying name input\n");
        goto err;
    }

    while (*cp) {
        char *bp = work;
        char *typestr = bp;
        unsigned char *valstr;
        int nid;
        int ismulti = nextismulti;
        nextismulti = 0;

        /* Collect the type */
        while (*cp && *cp != '=')
            *bp++ = *cp++;
        if (*cp == '\0') {
            BIO_printf(bio_err, "Hit end of string before finding the '='\n");
            goto err;
        }
        *bp++ = '\0';
        ++cp;

        /* Collect the value. */
        valstr = (unsigned char *)bp;
        for (; *cp && *cp != '/'; *bp++ = *cp++) {
            if (canmulti && *cp == '+') {
                nextismulti = 1;
                break;
            }
            if (*cp == '\\' && *++cp == '\0') {
                BIO_printf(bio_err, "escape character at end of string\n");
                goto err;
            }
        }
        *bp++ = '\0';

        /* If not at EOS (must be + or /), move forward. */
        if (*cp)
            ++cp;

        /* Parse */
        nid = OBJ_txt2nid(typestr);
        if (nid == NID_undef) {
            BIO_printf(bio_err, "Skipping unknown attribute \"%s\"\n", typestr);
            continue;
        }
        if (*valstr == '\0') {
            BIO_printf(bio_err, "No value provided for Subject Attribute %s, skipped\n", typestr);
            continue;
        }
        if (!X509_NAME_add_entry_by_NID(n, nid, chtype,
                                        valstr, strlen((char *)valstr),
                                        -1, ismulti ? -1 : 0)) {
            BIO_printf(bio_err, "Error adding name attribute \"/%s=%s\"\n",
                       typestr ,valstr);
            goto err;
        }
    }

    OPENSSL_free(work);
    return n;

 err:
    X509_NAME_free(n);
    OPENSSL_free(work);
    return NULL;
}
