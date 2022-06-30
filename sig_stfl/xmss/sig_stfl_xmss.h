#ifndef OQS_SIG_STFL_XMSS_H
#define OQS_SIG_STFL_XMSS_H

#include "../sig_stfl.h"

#ifdef OQS_SIG_STFL_alg_xmss_sha256_h10

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_sha256_h10_new(void);
int OQS_SIG_STFL_alg_xmss_sha256_h10_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha256_h10_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha256_h10_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_SIG_STFL_alg_xmss_sha256_h16

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_sha256_h16_new(void);
int OQS_SIG_STFL_alg_xmss_sha256_h16_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha256_h16_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha256_h16_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_SIG_STFL_alg_xmss_sha256_h20

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_sha256_h20_new(void);
int OQS_SIG_STFL_alg_xmss_sha256_h20_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha256_h20_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha256_h20_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_SIG_STFL_alg_xmss_sha512_h10

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_sha512_h10_new(void);
int OQS_SIG_STFL_alg_xmss_sha512_h10_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha512_h10_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha512_h10_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_SIG_STFL_alg_xmss_sha512_h16

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_sha512_h16_new(void);
int OQS_SIG_STFL_alg_xmss_sha512_h16_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha512_h16_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha512_h16_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_SIG_STFL_alg_xmss_sha512_h20

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_sha512_h20_new(void);
int OQS_SIG_STFL_alg_xmss_sha512_h20_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha512_h20_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_sha512_h20_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_SIG_STFL_alg_xmss_shake128_h10

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_shake128_h10_new(void);
int OQS_SIG_STFL_alg_xmss_shake128_h10_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake128_h10_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake128_h10_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_SIG_STFL_alg_xmss_shake128_h16

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_shake128_h16_new(void);
int OQS_SIG_STFL_alg_xmss_shake128_h16_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake128_h16_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake128_h16_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_SIG_STFL_alg_xmss_shake128_h20

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_shake128_h20_new(void);
int OQS_SIG_STFL_alg_xmss_shake128_h20_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake128_h20_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake128_h20_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_SIG_STFL_alg_xmss_shake256_h10

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_shake256_h10_new(void);
int OQS_SIG_STFL_alg_xmss_shake256_h10_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake256_h10_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake256_h10_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_SIG_STFL_alg_xmss_shake256_h16

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_shake256_h16_new(void);
int OQS_SIG_STFL_alg_xmss_shake256_h16_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake256_h16_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake256_h16_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#ifdef OQS_SIG_STFL_alg_xmss_shake256_h20

OQS_SIG_STFL *OQS_SIG_STFL_alg_xmss_shake256_h20_new(void);
int OQS_SIG_STFL_alg_xmss_shake256_h20_keypair(uint8_t *public_key, OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake256_h20_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const OQS_SECRET_KEY *secret_key);
int OQS_SIG_STFL_alg_xmss_shake256_h20_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#endif