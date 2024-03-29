#ifndef API_H
#define API_H

/*************************************************
 * Name:        XMSS_crypto_sign_keypair
 *
 * Description: Generates public and private key.
 *
 * Arguments:   - uint8_t *pk: pointer to output public key (allocated
 *                             array of CRYPTO_PUBLIC_KEY bytes)
 *              - uint8_t *sk: pointer to output private key (allocated
 *                             array of CRYPTO_SECRET_KEY bytes)
 *
 * Returns 0 (success), -1 otherwise
 **************************************************/
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int crypto_sign_keypair_mp(unsigned char *pk, unsigned char *sk);

/*************************************************
 * Name:        XMSS_crypto_sign
 *
 * Description: Computes signature.
 *
 * Arguments:   - uint8_t *sm:   pointer to output signature (of length CRYPTO_BYTES)
 *              - uint8_t *m:     pointer to message to be signed
 *              - uint8_t *sk:    pointer to bit-packed secret key
 *              - unsigned long long *smlen: pointer to output length of signature
 *              - unsigned long long mlen:    length of message
 *
 * Returns 0 (success), -1 otherwise
 **************************************************/
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen, unsigned char *sk);
int crypto_sign_mp(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen, unsigned char *sk);

/*************************************************
 * Name:        XMSS_crypto_sign_open
 *
 * Description: Verify signed message.
 *
 * Arguments:   
 *              - uint8_t *m: pointer to output message (allocated
 *                            array with smlen bytes), can be equal to sm
 *              - unsigned long long *mlen: pointer to output length of message
 *              - const uint8_t *sm: pointer to signed message
 *              - unsigned long long smlen: length of signed message
 *              - const uint8_t *pk: pointer to bit-packed public key
 *
 * Returns 0 if signed message could be verified correctly and -1 otherwise
 **************************************************/
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen, const unsigned char *pk);
int crypto_sign_open_mp(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen, const unsigned char *pk);

/*************************************************
 * Name:        XMSS_crypto_remaining_signatures
 *
 * Description: Return number of signatures left
 *
 * Arguments:   - unsigned long long *remain: remaining signatures
 *              - const uint8_t *sk: pointer to bit-packed private key
 *
 * Returns 0 (sucess), -1 otherwise
 **************************************************/
int crypto_remaining_signatures(unsigned long long *remain, const unsigned char *sk);

#endif 

