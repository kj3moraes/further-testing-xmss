#include "sig_stfl_xmss.h"
#include "./external/params.h"
#include "./external/xmss.h"

int OQS_SIG_STFL_alg_xmss_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key) {
    if (secret_key == NULL || public_key == NULL) return -1;
    
    return xmss_keypair(public_key, secret_key, secret_key->oid);
}

int OQS_SIG_STFL_alg_xmss_sign(uint8_t *signature, size_t signature_length, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key) {
    if (secret_key == NULL || message == NULL || signature == NULL) return -1;
    
    return xmss_sign(secret_key, signature, signature_length, message, message_len);
}

int OQS_SIG_STFL_alg_xmss_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
    if (message == NULL || signature == NULL || public_key == NULL) return -1;
    
    return xmss_sign_open(message, message_len, signature, signature_len, public_key);
}

int OQS_SIG_STFL_alg_xmssmt_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key) {
    if (secret_key == NULL || public_key == NULL) return -1;
    
    return xmssmt_keypair(public_key, secret_key, secret_key->oid);
}

int OQS_SIG_STFL_alg_xmssmt_sign(uint8_t *signature, size_t signature_length, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key) {
    if (secret_key == NULL || message == NULL || signature == NULL) return -1;
    
    return xmssmt_sign(secret_key, signature, signature_length, message, message_len);
}

int OQS_SIG_STFL_alg_xmssmt_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
    if (message == NULL || signature == NULL || public_key == NULL) return -1;
    
    return xmssmt_sign_open(message, message_len, signature, signature_len, public_key);
}