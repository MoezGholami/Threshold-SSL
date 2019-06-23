static const char *PRIV_KEY_FILE =                      "rootkey.key";
static const char *DIGEST_HASH_OUTPUT_FILE_NAME =       "digest_pipe";
static const char *SIGNATURE_INPUT_FILE_NAME    =       "signature_pipe";
#define     bool            char
#define     true            1
#define     false           0

#include <stdio.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

int read_digest(char **digest);
    int digit_to_byte(char c);
EC_KEY *load_private_key(const char *key_path);
bool write_out_the_signature(const char *signature_path, ECDSA_SIG *signature);

int main(int argc, char *argv[]) {
    unsigned char *digest = NULL;
    int digest_length;
    EC_KEY *prkey;
    ECDSA_SIG *signature;

    digest_length = read_digest((char **)(&digest));
    if(digest_length <= 0)
        fprintf(stderr, "ERROR: Could not read the digest. Aborting ...\n");

    prkey = load_private_key(PRIV_KEY_FILE);
    if(!prkey)
        fprintf(stderr, "ERROR: Could not read the private key. Aborting ...\n");

    signature = ECDSA_do_sign(digest, digest_length, prkey);
    if(!signature)
        fprintf(stderr, "ERROR: Could not sign the digest. Aborting ...\n");


    bool write_success = write_out_the_signature(SIGNATURE_INPUT_FILE_NAME, signature);

    free(digest);
    EC_KEY_free(prkey);
    ECDSA_SIG_free(signature);

    if(!write_success) {
        fprintf(stderr, "ERROR: Could not write the signature. Failed!\n");
        return 1;
    }
    return 0;
}

int read_digest(char **digest) {
    size_t limit;
    ssize_t bytes_read;
    FILE *f;

    *digest = NULL;
    limit = 0;
    f = fopen(DIGEST_HASH_OUTPUT_FILE_NAME, "r");

    if(!f)
        return 0;
    bytes_read = getline(digest, &limit, f);
    if(bytes_read <= 0)
        return 0;
    if(fclose(f) != 0)
        return 0;

    unsigned char *binary = (unsigned char *)(*digest);
    for(unsigned i = 0; i < bytes_read; i+=2)
        binary[i/2] = digit_to_byte((*digest)[i])*16 + digit_to_byte((*digest)[i+1]);
    return (int)(bytes_read/2);
}

int digit_to_byte(char c) {
    if( '0' <= c && '9' >= c )
        return (int)(c - '0');
    if( 'a' <= c && 'f' >= c )
        return (int)(c - 'a') + 10;
    if( 'A' <= c && 'F' >= c )
        return (int)(c - 'A') + 10;
    return -1;
}

EC_KEY *load_private_key(const char *key_path) {
    EVP_PKEY *pk;
    FILE    *f;
    EC_KEY *result;

    if (! (pk=EVP_PKEY_new())) {
        fprintf(stderr, "ERROR: Error in creating private key data structure.\n");
        return NULL;
    }
    if (! (f = fopen (key_path, "r"))) {
        fprintf(stderr, "ERROR: Error reading signing private key file.\n");
        EVP_PKEY_free(pk);
        return NULL;
    }
    PEM_read_PrivateKey( f, &pk, NULL, NULL);
    if (!pk) {
        fprintf(stderr, "ERROR: Error importing key content from file.\n");
        EVP_PKEY_free(pk);
        fclose(f);
        return NULL;
    }
    if (fclose(f)) {
        fprintf(stderr, "ERROR: Error in closing key content file.\n");
        EVP_PKEY_free(pk);
        return NULL;
    }

    result = EVP_PKEY_get1_EC_KEY(pk);
    EVP_PKEY_free(pk);
    return result;
}

bool write_out_the_signature(const char *signature_path, ECDSA_SIG *signature) {
    FILE *f;

    f = fopen(signature_path, "w");
    if(!f) {
        fprintf(stderr, "ERROR: Could not open signature output file.\n");
        return false;
    }
    if(!BN_print_fp(f, ECDSA_SIG_get0_r(signature))) {
        fprintf(stderr, "ERROR: Could not write the signature R number.\n");
        return false;
    }
    fprintf(f, "\n");
    if(!BN_print_fp(f, ECDSA_SIG_get0_s(signature))) {
        fprintf(stderr, "ERROR: Could not write the signature S number.\n");
        return false;
    }
    if(fclose(f)) {
        fprintf(stderr, "ERROR: Could not close the signature output file.\n");
        return false;
    }
    return true;
}
