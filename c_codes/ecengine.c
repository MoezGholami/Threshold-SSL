static const char *ENGINE_ID                    =       "Mozecengine";
static const char *ENGINE_NAME                  =       "Elliptic Curv Engine Powered by Moez";
static const char *DIGEST_HASH_OUTPUT_FILE_NAME =       "digest_pipe";
static const char *SIGNATURE_INPUT_FILE_NAME    =       "signature_pipe";




#include <stdio.h>
#include <openssl/engine.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>

#define     bool            char
#define     true            1
#define     false           0

static EC_KEY_METHOD *setup_ecdsa_method(void);
static ECDSA_SIG *mozecengine_ecdsa_sign (const unsigned char *digest, int digest_len,
        const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *key_template);
    static bool check_paramethers(int digest_len, const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *key_template);
    static bool write_digest_to_output(const unsigned char *digest, int digest_len);
    static bool read_signature_from_input(ECDSA_SIG **signature);
static int mozecengine_ecdsa_sign_buffered(int type, const unsigned char *digest, int dlen,
        unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);
static int mozecengine_ecdsa_sign_setup (EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp);
static int mozecengine_ecdsa_do_verify (const unsigned char *digest, int digest_len,
        const ECDSA_SIG *ecdsa_sig, EC_KEY *eckey);
static int mozecengine_ecdsa_do_verify_buffered(int type, const unsigned char *digest, int digest_len,
        const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);

static int bind(ENGINE *e, const char *id) {
    EC_KEY_METHOD *mozecengine_ecdsa_method = setup_ecdsa_method();
    if (
            !mozecengine_ecdsa_method
        ||	!ENGINE_set_id(e, ENGINE_ID)
        ||	!ENGINE_set_name(e, ENGINE_NAME)
        ||	!ENGINE_set_EC(e, mozecengine_ecdsa_method)
       ) {
        fprintf(stderr, "engine setup failed\n");
        return false;
    }
    return true;
}

EC_KEY_METHOD *setup_ecdsa_method(void) {
    EC_KEY_METHOD *result = EC_KEY_METHOD_new(NULL);
    if (result) {
        EC_KEY_METHOD_set_sign(result, mozecengine_ecdsa_sign_buffered, mozecengine_ecdsa_sign_setup, mozecengine_ecdsa_sign);
        EC_KEY_METHOD_set_verify(result, mozecengine_ecdsa_do_verify_buffered, mozecengine_ecdsa_do_verify);
    }
    return result;
}

ECDSA_SIG *mozecengine_ecdsa_sign (const unsigned char *digest, int digest_len,
        const BIGNUM *kinv, const BIGNUM *rp,
        EC_KEY *key_template) {
    printf("INFO: Mozecengine ecdsa sign function ...\n");
    printf("INFO: The passed key is only a template. Its content except its curve name is never used.\n");
    if(!check_paramethers(digest_len, kinv, rp, key_template)) {
        fprintf(stderr, "Aborting signature creation due to bad input arguments.\n");
        return false;
    }
    if(!write_digest_to_output(digest, digest_len)) {
        fprintf(stderr, "Could not write out the digest to the output to sign.\n");
        return false;
    }
    ECDSA_SIG *result = NULL;
    if(!read_signature_from_input(&result)) {
        fprintf(stderr, "Could not read the signature from the input file.\n");
        return false;
    }
    return result;
}

bool check_paramethers(int digest_len, const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *key_template) {
    if(digest_len <= 0)
        fprintf(stderr, "The digest length must be positive.\n");
    else if(kinv || rp)
        fprintf(stderr, "Our algorithm inherently cannot support know **kinv** and **rp**. It's secretly shared.\n");
    else
        return true;
    return false;
}

bool write_digest_to_output(const unsigned char *digest, int digest_len) {
    FILE *f = fopen(DIGEST_HASH_OUTPUT_FILE_NAME, "w");
    unsigned int t = 0;
    if(!f)
        return false;
    for(int i = 0; i < digest_len; i++) {
        t = digest[i];
        t = t & 0xFF;
        if(fprintf(f, "%02X", t) <= 0)
            return false;
    }
    if(fprintf(f, "\n") <= 0)
        return false;
    if(fclose(f) != 0)
        return false;
    return true;
}

bool read_signature_from_input(ECDSA_SIG **signature) {
    size_t limit = 0;
    char *r_str = NULL, *s_str = NULL;
    FILE *f = fopen(SIGNATURE_INPUT_FILE_NAME, "r");
    if(!f)
        return false;
    if(getline(&r_str, &limit, f) <= 0)
        return false;
    if(getline(&s_str, &limit, f) <= 0)
        return false;
    if(fclose(f) != 0)
        return false;
    BIGNUM *r = BN_new(), *s = BN_new();
    if(!r || !s)
        return false;
    if(!BN_hex2bn(&r, r_str) || !BN_hex2bn(&s, s_str))
        return false;
    free(r_str);
    free(s_str);
    ECDSA_SIG *result = ECDSA_SIG_new();
    if(!result)
        return false;
    if(!ECDSA_SIG_set0(result, r, s))
        return false;
    *signature = result;
    return true;
}

static int mozecengine_ecdsa_sign_buffered(int type, const unsigned char *digest, int dlen,
        unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey) {
    ECDSA_SIG *s;

    s = mozecengine_ecdsa_sign(digest, dlen, kinv, r, eckey);
    if (s == NULL) {
        *siglen = 0;
        return false;
    }
    *siglen = i2d_ECDSA_SIG(s, &sig);
    ECDSA_SIG_free(s);
    return true;
}

int mozecengine_ecdsa_sign_setup (EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
        BIGNUM **rp) {
    return true;
}
int mozecengine_ecdsa_do_verify (const unsigned char *digest, int digest_len,
        const ECDSA_SIG *ecdsa_sig, EC_KEY *eckey) {
    fprintf(stderr, "Mozecengine only supports signing. Verification can be done anywhere else\n");
    return false;
}

static int mozecengine_ecdsa_do_verify_buffered(int type, const unsigned char *digest, int digest_len,
        const unsigned char *sigbuf, int sig_len, EC_KEY *eckey) {
    return mozecengine_ecdsa_do_verify(digest, digest_len, NULL, eckey);
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
