
#include <stdlib.h>

#include "./external/xmss.h"
#include "./external/params.h"
#include "sig_stfl_xmss.h"

// ======================== XMSS10-SHA256 ======================== //

OQS_SIG_STFL *OQS_SIG_STFL_xmss_sha256_h10() {
    
    OQS_SIG_STFL *sig = (OQS_SIG_STFL *)malloc(sizeof(OQS_SIG_STFL));
    if (sig == NULL) {
        return NULL;
    }
    sig->method_name = "XMSS-SHA2_10_256";
    sig->alg_version = "..."; 

    // Check how true this is
    sig->claimed_nist_level = 2;
    sig->euf_cma = true;

    sig->keypair = OQS_SIG_STFL_alg_xmss_keypair;
    sig->sign = OQS_SIG_STFL_alg_xmss_sign;
    sig->verify = OQS_SIG_STFL_alg_xmss_verify;

    return sig;
}

OQS_SECRET_KEY *OQS_SECRET_KEY_XMSS_SHA256_H10_new() {

    // Initialize the secret key in the heap with adequate memory
    OQS_SECRET_KEY *sk = malloc(sizeof(OQS_SECRET_KEY));
    if (sk == NULL) return NULL;
    sk->oid = 0x00000001;

    // Convert the oid into a XMSS parameters list and extract the length of the secret key.
    xmss_params par;
    xmss_parse_oid(&par, sk->oid);
    sk->length_secret_key = par.sk_bytes;

    // Initialize the key with length_secret_key amount of bytes.
    sk->secret_key = (uint8_t *)malloc(sk->length_secret_key * sizeof(uint8_t));
}

// ================================================================ //

// ======================== XMSS16-SHA256 ======================== //

OQS_SIG_STFL *OQS_SIG_STFL_xmss_sha256_h16() {
    
    OQS_SIG_STFL *sig = (OQS_SIG_STFL *)malloc(sizeof(OQS_SIG_STFL));
    if (sig == NULL) {
        return NULL;
    }
    sig->method_name = "XMSS-SHA2_16_256";
    sig->alg_version = "..."; 

    // Check how true this is
    sig->claimed_nist_level = 2;
    sig->euf_cma = true;

    sig->keypair = OQS_SIG_STFL_alg_xmss_keypair;
    sig->sign = OQS_SIG_STFL_alg_xmss_sign;
    sig->verify = OQS_SIG_STFL_alg_xmss_verify;

    return sig;
}

OQS_SECRET_KEY *OQS_SECRET_KEY_XMSS_SHA256_H16_new() {

    // Initialize the secret key in the heap with adequate memory
    OQS_SECRET_KEY *sk = malloc(sizeof(OQS_SECRET_KEY));
    if (sk == NULL) return NULL;
    sk->oid = 0x00000002;

    // Convert the oid into a XMSS parameters list and extract the length of the secret key.
    xmss_params par;
    xmss_parse_oid(&par, sk->oid);
    sk->length_secret_key = par.sk_bytes;

    // Initialize the key with length_secret_key amount of bytes.
    sk->secret_key = (uint8_t *)malloc(sk->length_secret_key * sizeof(uint8_t));
}

// ================================================================ //

// ======================== XMSS20-SHA256 ======================== //

OQS_SIG_STFL *OQS_SIG_STFL_xmss_sha256_h20() {
    
    OQS_SIG_STFL *sig = (OQS_SIG_STFL *)malloc(sizeof(OQS_SIG_STFL));
    if (sig == NULL) {
        return NULL;
    }
    sig->method_name = "XMSS-SHA2_20_256";
    sig->alg_version = "..."; 

    // Check how true this is
    sig->claimed_nist_level = 2;
    sig->euf_cma = true;

    sig->keypair = OQS_SIG_STFL_alg_xmss_keypair;
    sig->sign = OQS_SIG_STFL_alg_xmss_sign;
    sig->verify = OQS_SIG_STFL_alg_xmss_verify;

    return sig;
}

OQS_SECRET_KEY *OQS_SECRET_KEY_XMSS_SHA256_H20_new() {

    // Initialize the secret key in the heap with adequate memory
    OQS_SECRET_KEY *sk = malloc(sizeof(OQS_SECRET_KEY));
    if (sk == NULL) return NULL;
    sk->oid = 0x00000003;

    // Convert the oid into a XMSS parameters list and extract the length of the secret key.
    xmss_params par;
    xmss_parse_oid(&par, sk->oid);
    sk->length_secret_key = par.sk_bytes;

    // Initialize the key with length_secret_key amount of bytes.
    sk->secret_key = (uint8_t *)malloc(sk->length_secret_key * sizeof(uint8_t));
}

// ================================================================ //


int OQS_SIG_STFL_alg_xmss_sha256_h10_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key) {
    return xmss_keypair(public_key, secret_key, secret_key->oid);
}

int OQS_SIG_STFL_alg_xmss_sha256_h10_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, OQS_SECRET_KEY *secret_key) {
    return xmss_sign(secret_key, signature, signature_len, message, message_len);
}

int OQS_SIG_STFL_alg_xmss_sha256_h10_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
    return xmss_sign_open(message, message_len, signature, signature_len, public_key);
}
