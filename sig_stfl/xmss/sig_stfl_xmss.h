#ifndef OQS_SIG_STFL_XMSS_H
#define OQS_SIG_STFL_XMSS_H

#include "../sig_stfl.h"

#ifdef OQS_ENABLE_SIG_STFL_XMSS_SHA256_H10

OQS_SECRET_KEY *OQS_SECRET_KEY_XMSS_SHA256_H10_new();

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_sha256_h10_new(void);
int OQS_SIG_STFL_alg_xmss_sha256_h10_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha256_h10_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha256_h10_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_ENABLE_SIG_STFL_XMSS_SHA256_H16

OQS_SECRET_KEY *OQS_SECRET_KEY_XMSS_SHA256_H16_new();

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_sha256_h16_new(void);
int OQS_SIG_STFL_alg_xmss_sha256_h16_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha256_h16_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha256_h16_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_ENABLE_SIG_STFL_XMSS_SHA256_H20

OQS_SECRET_KEY *OQS_SECRET_KEY_XMSS_SHA256_H20_new();

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_sha256_h20_new(void);
int OQS_SIG_STFL_alg_xmss_sha256_h20_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha256_h20_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha256_h20_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_ENABLE_SIG_STFL_XMSS_SHA512_H10

OQS_SECRET_KEY *OQS_SECRET_KEY_XMSS_SHA512_H10_new();

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_sha512_h10_new(void);
int OQS_SIG_STFL_alg_xmss_sha512_h10_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha512_h10_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha512_h10_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_ENABLE_SIG_STFL_XMSS_SHA512_H16

OQS_SECRET_KEY *OQS_SECRET_KEY_XMSS_SHA512_H16_new();

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_sha512_h16_new(void);
int OQS_SIG_STFL_alg_xmss_sha512_h16_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha512_h16_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha512_h16_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_ENABLE_SIG_STFL_XMSS_SHA512_H20

OQS_SECRET_KEY *OQS_SECRET_KEY_XMSS_SHA512_H20_new();

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_sha512_h20_new(void);
int OQS_SIG_STFL_alg_xmss_sha512_h20_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha512_h20_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha512_h20_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_ENABLE_SIG_STFL_XMSS_SHAKE128_H10

OQS_SECRET_KEY *OQS_SECRET_KEY_XMSS_ShAKE128_H10_new();

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_shake128_h10_new(void);
int OQS_SIG_STFL_alg_xmss_shake128_h10_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake128_h10_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake128_h10_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_ENABLE_SIG_STFL_XMSS_SHAKE128_H16

OQS_SECRET_KEY *OQS_SECRET_KEY_XMSS_ShAKE128_H16_new();

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_shake128_h16_new(void);
int OQS_SIG_STFL_alg_xmss_shake128_h16_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake128_h16_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake128_h16_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_ENABLE_SIG_STFL_XMSS_SHAKE128_H20

OQS_SECRET_KEY *OQS_SECRET_KEY_XMSS_ShAKE128_H20_new();

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_shake128_h20_new(void);
int OQS_SIG_STFL_alg_xmss_shake128_h20_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake128_h20_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake128_h20_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_ENABLE_SIG_STFL_XMSS_SHAKE256_H10

OQS_SECRET_KEY *OQS_SECRET_KEY_XMSS_ShAKE256_H10_new();

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_shake256_h10_new(void);
int OQS_SIG_STFL_alg_xmss_shake256_h10_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake256_h10_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake256_h10_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_ENABLE_SIG_STFL_XMSS_SHAKE256_H16

OQS_SECRET_KEY *OQS_SECRET_KEY_XMSS_ShAKE256_H16_new();

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_shake256_h16_new(void);
int OQS_SIG_STFL_alg_xmss_shake256_h16_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake256_h16_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake256_h16_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_ENABLE_SIG_STFL_XMSS_SHAKE256_H20

OQS_SECRET_KEY *OQS_SECRET_KEY_XMSS_ShAKE256_H20_new();

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_shake256_h20_new(void);
int OQS_SIG_STFL_alg_xmss_shake256_h20_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake256_h20_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake256_h20_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif


/* ===
    ADD THE XMSS^MT VARIANTS HERE
    ===
*/


// ---------------------------- FUNCTIONS INDEPENDENT OF VARIANT -----------------------------------------

extern int OQS_SIG_STFL_alg_xmss_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);

extern int OQS_SIG_STFL_alg_xmss_sign(uint8_t *signature, size_t signature_length, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);

extern int OQS_SIG_STFL_alg_xmss_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

extern int OQS_SIG_STFL_alg_xmssmt_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);

extern int OQS_SIG_STFL_alg_xmssmt_sign(uint8_t *signature, size_t signature_length, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);

extern int OQS_SIG_STFL_alg_xmssmt_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

// --------------------------------------------------------------------------------------------------------


#endif /* OQS_SIG_STFL_XMSS_H */