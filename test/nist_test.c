// SPDX-License-Identifier: Public domain
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "../api.h"
#include "../nist_params.h"    // Include NIST parameter header
#include "../xmss.h"           // Include NIST XMSS header, to test no. of remaining signature
#include "../params.h"         // Incnlude predefined params
#include "../thread_wrapper.h" // Include thread to CPU cores at run time: XMSS_search_cpu()

#define XMSS_SIGNATURES 64

#define CALC(start, stop) ((stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3)

/*
 * This array collect the performance number
 * and then use it to compute average and median number
 */
unsigned long long t[XMSS_SIGNATURES];

#if DEBUG
static void print_hex(const unsigned char *a, int length, const char *string)
{
    printf("%s[%d] = \n", string, length);
    for (int i = 0; i < length; i++)
    {
        printf("%02x", a[i]);
    }
    printf("\n");
}
#endif

static int cmp_llu(const void *a, const void *b)
{
    if (*(unsigned long long *)a < *(unsigned long long *)b)
        return -1;
    if (*(unsigned long long *)a > *(unsigned long long *)b)
        return 1;
    return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
    qsort(l, llen, sizeof(unsigned long long), cmp_llu);

    if (llen % 2)
        return l[llen / 2];
    else
        return (l[llen / 2 - 1] + l[llen / 2]) / 2;
}

static unsigned long long average(unsigned long long *t, size_t tlen)
{
    unsigned long long acc = 0;
    for (size_t i = 0; i < tlen; i++)
    {
        acc += t[i];
    }
    return acc / tlen;
}

static void print_results(unsigned long long *t, size_t tlen)
{
    printf("\tmedian        : %llu us\n", median(t, tlen));
    printf("\taverage       : %llu us\n", average(t, tlen));
    printf("\n");
}

/*
 * Test keygen
 */
int test_keygen(unsigned char *pk, unsigned char *sk)
{
    struct timespec start, stop;
    int ret;
    double result;

#if MP == 0
    printf("Generating keypair.. %s\n", XMSS_OID);
#else
    printf("Generating keypair MP.. %s\n", XMSS_OID);
#endif
    clock_gettime(CLOCK_REALTIME, &start);
#if MP == 0
    ret = crypto_sign_keypair(pk, sk);
#else
    ret = crypto_sign_keypair_mp(pk, sk);
#endif
    clock_gettime(CLOCK_REALTIME, &stop);

    result = CALC(start, stop);
    printf("took %lf us (%.2lf sec)\n", result, result / 1e6);

    return ret;
}

/*
 * Test Sign
 */
int test_sign(unsigned char *sm, unsigned long long *smlen,
              const unsigned char *m, unsigned long long mlen, unsigned char *sk)
{
    struct timespec start, stop;
    int ret;
#if MP == 0
    printf("Creating %d signatures..\n", XMSS_SIGNATURES);
#else
    printf("Creating %d MP signatures..\n", XMSS_SIGNATURES);
#endif
    for (int i = 0; i < XMSS_SIGNATURES; i++)
    {
        clock_gettime(CLOCK_REALTIME, &start);
#if MP == 0
        ret = crypto_sign(sm, smlen, m, mlen, sk);
#else
        ret = crypto_sign_mp(sm, smlen, m, mlen, sk);
#endif
        clock_gettime(CLOCK_REALTIME, &stop);

        t[i] = CALC(start, stop);

        if (*smlen != CRYPTO_BYTES + mlen)
        {
            printf("  X smlen incorrect [%llu != %llu]!\n", *smlen, CRYPTO_BYTES + mlen);
            break;
        }
        if (ret)
        {
            break;
        }
    }
    print_results(t, XMSS_SIGNATURES);

    return ret;
}

/*
 * Test Verify
 */
int test_verify(unsigned char *mout, unsigned long long *moutlen,
                const unsigned char *sm, unsigned long long smlen, const unsigned char *pk,
                unsigned char *m, const unsigned long long mlen)
{
    struct timespec start, stop;
    int ret;
#if MP == 0
    printf("Verifying %d signatures..\n", XMSS_SIGNATURES);
#else
    printf("Verifying %d MP signatures..\n", XMSS_SIGNATURES);
#endif
    for (int i = 0; i < XMSS_SIGNATURES; i++)
    {
        clock_gettime(CLOCK_REALTIME, &start);
#if MP == 0
        ret = crypto_sign_open(mout, moutlen, sm, smlen, pk);
#else
        ret = crypto_sign_open_mp(mout, moutlen, sm, smlen, pk);
#endif
        clock_gettime(CLOCK_REALTIME, &stop);

        t[i] = CALC(start, stop);

        if (*moutlen != mlen)
        {
            printf("  X mlen incorrect [%llu != %llu]!\n", *moutlen, mlen);
            ret = -1;
            break;
        }

        if (memcmp(mout, m, mlen))
        {
            printf("  mout incorrect [%s != %s]\n", mout, m);
            ret = -1;
            break;
        }

        if (ret)
        {
            break;
        }
    }
    print_results(t, XMSS_SIGNATURES);

    return ret;
}

/*
 * Testing remaining signatures
 */
int test_remain(unsigned char *sk)
{
    unsigned long long remain = 0, max;
    uint32_t oid = 0;
    xmss_params params;
    int ret;
    ret = crypto_remaining_signatures(&remain, sk);

    for (int i = 0; i < XMSS_OID_LEN; i++)
    {
        oid |= sk[XMSS_OID_LEN - i - 1] << (i * 8);
    }

#if XMSSMT
    if (xmssmt_parse_oid(&params, oid))
#else
    if (xmss_parse_oid(&params, oid))
#endif
    {
        return -1;
    }
    max = ((1ULL << params.full_height) - 1);

    printf("used = %lld, remain = %lld, max = %lld\n", max - remain, remain, max);

    // Incorrect count;
    if (max - remain != XMSS_SIGNATURES)
    {
        printf("    Incorrect used signatures\n");
        return 1;
    }

    return ret;
}

int main(void)
{
    // Keygen test
    int ret;
    unsigned char pk[CRYPTO_PUBLIC_KEY], sk[CRYPTO_SECRET_KEY];
    unsigned long long smlen, mlen, mlen_out;

    // Signature test
    unsigned char m[] = "\nThis is a test from SandboxAQ\n";
    mlen = sizeof(m);
    // Verify test
    unsigned char *sm = malloc(CRYPTO_BYTES + mlen);
    unsigned char *mout = malloc(CRYPTO_BYTES + mlen);

    XMSS_search_cpu();
    printf("core, max = %d, %d\n", XMSS_num_cores, XMSS_num_cores_max);

    ret = test_keygen(pk, sk);

    if (ret)
    {
        printf("    Unable to generate keypair\n");
        return 1;
    }

#if DEBUG
    print_hex(pk, CRYPTO_PUBLIC_KEY, "pk");
    print_hex(sk, CRYPTO_SECRET_KEY, "sk");
#endif

    ret |= test_sign(sm, &smlen, m, mlen, sk);

    if (ret)
    {
        printf("    Unable to generate signature\n");
        return 1;
    }

#if DEBUG
    print_hex(m, mlen, "message");
    print_hex(sm, smlen, "signature");
#endif

    ret |= test_verify(mout, &mlen_out, sm, smlen, pk, m, mlen);

    if (ret)
    {
        printf("    Unable to verify signature\n");
        return 1;
    }

    ret |= test_remain(sk);

    if (ret)
    {
        printf("    Unable to check remaining signature\n");
        return 1;
    }

    free(sm);
    free(mout);

    return 0;
}
