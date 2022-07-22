#include <oqs/common.h>
#include <stdio.h>
#include "api.h"
#include "params.h"
#include "nist_params.h"
#include "xmss.h"

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    xmss_params params;
    uint32_t oid;
    int ret = 0;

    ret |= XMSS_STR_TO_OID(&oid, XMSS_OID);
    if (ret)
    {
#if DEBUG
        printf("Did not recognize %s!\n", XMSS_OID);
#endif
        return OQS_ERROR;
    }

    ret |= XMSS_PARSE_OID(&params, oid);
    if (ret)
    {
#if DEBUG
        printf("Could not parse OID for %s!\n", XMSS_OID);
#endif
        return OQS_ERROR;
    }
#if DEBUG
    printf("sklen, pklen, siglen = %llu, %u, %u\n", params.sk_bytes, params.pk_bytes, params.sig_bytes);
#endif

    ret |= XMSS_KEYPAIR(pk, sk, oid);
    if (ret)
    {
#if DEBUG
        printf("Error generating keypair %d\n", ret);
#endif
        return OQS_ERROR;
    }

    return OQS_SUCCESS;
}

int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen, unsigned char *sk)
{
    int ret = XMSS_SIGN(sk, sm, smlen, m, mlen);
    if (ret)
    {
#if DEBUG
        printf("Error generating signature %d\n", ret);
#endif
        return OQS_ERROR;
    }

    return OQS_SUCCESS;
}

int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen, const unsigned char *pk)
{
    if (XMSS_SIGN_OPEN(m, mlen, sm, smlen, pk))
    {
#if DEBUG
        printf("Error verifying signature %d\n", ret);
#endif
        return OQS_ERROR;
    }

    return OQS_SUCCESS;
}

int crypto_remaining_signatures(unsigned long long *remain, const unsigned char *sk)
{
    if (XMSS_REMAINING_SIG(remain, sk))
    {
#if DEBUG
        printf("Error counting remaining signatures\n");
#endif
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}


int crypto_sign_keypair_mp(unsigned char *pk, unsigned char *sk)
{
    xmss_params params;
    uint32_t oid;
    int ret = 0;

    ret |= XMSS_STR_TO_OID(&oid, XMSS_OID);
    if (ret)
    {
#if DEBUG
        printf("Did not recognize %s!\n", XMSS_OID);
#endif
        return OQS_ERROR;
    }

    ret |= XMSS_PARSE_OID(&params, oid);
    if (ret)
    {
#if DEBUG
        printf("Could not parse OID for %s!\n", XMSS_OID);
#endif
        return OQS_ERROR;
    }
#if DEBUG
    printf("sklen, pklen, siglen = %llu, %u, %u\n", params.sk_bytes, params.pk_bytes, params.sig_bytes);
#endif

    ret |= XMSS_KEYPAIR_MP(pk, sk, oid);
    if (ret)
    {
#if DEBUG
        printf("Error generating keypair %d\n", ret);
#endif
        return OQS_ERROR;
    }

    return OQS_SUCCESS;
}

int crypto_sign_mp(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen, unsigned char *sk)
{
    int ret = XMSS_SIGN_MP(sk, sm, smlen, m, mlen);
    if (ret)
    {
#if DEBUG
        printf("Error generating signature %d\n", ret);
#endif
        return OQS_ERROR;
    }

    return OQS_SUCCESS;
}

int crypto_sign_open_mp(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen, const unsigned char *pk)
{
    if (XMSS_SIGN_OPEN_MP(m, mlen, sm, smlen, pk))
    {
#if DEBUG
        printf("Error verifying signature %d\n", ret);
#endif
        return OQS_ERROR;
    }

    return OQS_SUCCESS;
}
