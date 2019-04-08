/*
 * This program intends to simulate the following terminal command: 
 * "openssl req -x509 -new -nodes -key mozroot.key -sha256 -days 3660 -out mozrootca.crt"
 * All file references and passphrases are static for the sake of simplicity.
 *
 */

#define     ROOT_KEY_FILE       "mozroot.key"
#define     ROOT_KEY_PASS       "moez"
#define     CERT_OUTPUT_FILE    "mozrootca.crt"

typedef     char    bool;
#define     true            1
#define     false           0
#define     NULL            0


#include <stdio.h>
#include <stdlib.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>

void setup(BIO **bio_err);
bool make_certificate(X509 **x509, EVP_PKEY **pkey, BIO *bio_err);
void teardown(X509 *x509, EVP_PKEY *pkey, BIO *bio_err);

int main(int argc, char **argv) {
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

bool load_private_key(EVP_PKEY **pkey, BIO *bio_err);
bool mkcert(X509 **x509p, EVP_PKEY *pk, BIO *bio_err, int bits, int serial, int days);
bool writeout_certificate_file(X509 *x509, BIO *bio_err);

bool make_certificate(X509 **x509, EVP_PKEY **pkey, BIO *bio_err) {
    if (load_private_key(pkey, bio_err) == false)
        return false;

    if (mkcert(x509, *pkey, bio_err, 512, 123, 365) == false) {
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

int add_ext(X509 *cert, int nid, char *value);
bool mkcert(X509 **x509p, EVP_PKEY *pk, BIO *bio_err, int bits, int serial, int days) {
    X509 *x;
    X509_NAME *name=NULL;

    if ((x=X509_new()) == NULL) {
        BIO_printf(bio_err, "Error in creating X509 data structure.\n");
        return false;
    }

    X509_set_version(x,3);
    ASN1_INTEGER_set(X509_get_serialNumber(x),serial);
    X509_gmtime_adj(X509_get_notBefore(x),0);
    X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
    X509_set_pubkey(x,pk);

    name=X509_get_subject_name(x);

    /* This function creates and adds the entry, working out the
     * correct string type and performing checks on its length.
     * Normally we'd check the return value for errors...
     */
    X509_NAME_add_entry_by_txt(name,"C",
            MBSTRING_ASC, (unsigned char *)"UK", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"CN",
            MBSTRING_ASC, (unsigned char *)"OpenSSL Group", -1, -1, 0);
    /* Its self signed so set the issuer name to be the same as the
     * subject.
     */
    X509_set_issuer_name(x,name);

    /* Add various extensions: standard extensions */
    add_ext(x, NID_basic_constraints, (char *)"critical,CA:TRUE");
    add_ext(x, NID_key_usage, (char *)"critical,keyCertSign,cRLSign");

    add_ext(x, NID_subject_key_identifier, (char *)"hash");

    /* Some Netscape specific extensions */
    add_ext(x, NID_netscape_cert_type, (char *)"sslCA");

    add_ext(x, NID_netscape_comment, (char *)"example comment extension");


    /* Maybe even add our own extension based on existing */
    {
        int nid;
        nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
        X509V3_EXT_add_alias(nid, NID_netscape_comment);
        add_ext(x, nid, (char *)"example comment alias");
    }

    if (X509_sign(x,pk,EVP_sha256()) == false) {
        BIO_printf(bio_err, "Error in signing the certificate.\n");
        return false;
    }

    *x509p=x;
    return true;
}

/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */
int add_ext(X509 *cert, int nid, char *value) {
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
