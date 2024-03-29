#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"
#include "hash.h"
#include "wots.h"
#include "hash_address.h"
#include "params.h"
#include "thread_wrapper.h"

/**
 * Helper method for pseudorandom key generation.
 * Expands an n-byte array into a len*n byte array using the `prf` function.
 */
static void expand_seed(const xmss_params *params,
                        unsigned char *outseeds, const unsigned char *inseed)
{
    uint32_t i;
    unsigned char ctr[32];

    for (i = 0; i < params->wots_len; i++)
    {
        ull_to_bytes(ctr, 32, i);
        prf(params, outseeds + i * params->n, ctr, inseed);
    }
}

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
static void gen_chain(const xmss_params *params,
                      unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, params->n);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start + steps) && i < params->wots_w; i++)
    {
        set_hash_addr(addr, i);
        thash_f(params, out, out, pub_seed, addr);
    }
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w(const xmss_params *params,
                   int *output, const int out_len, const unsigned char *input)
{
    int in = 0;
    int out = 0;
    unsigned char total;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++)
    {
        if (bits == 0)
        {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= params->wots_log_w;
        output[out] = (total >> bits) & (params->wots_w - 1);
        out++;
    }
}

/* Computes the WOTS+ checksum over a message (in base_w). */
static void wots_checksum(const xmss_params *params,
                          int *csum_base_w, const int *msg_base_w)
{
    int csum = 0;
    unsigned char csum_bytes[(params->wots_len2 * params->wots_log_w + 7) / 8];
    unsigned int i;

    /* Compute checksum. */
    for (i = 0; i < params->wots_len1; i++)
    {
        csum += params->wots_w - 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << (8 - ((params->wots_len2 * params->wots_log_w) % 8));
    ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w(params, csum_base_w, params->wots_len2, csum_bytes);
}

/* Takes a message and derives the matching chain lengths. */
static void chain_lengths(const xmss_params *params,
                          int *lengths, const unsigned char *msg)
{
    base_w(params, lengths, params->wots_len1, msg);
    wots_checksum(params, lengths + params->wots_len1, lengths);
}

/**
 * WOTS key generation. Takes a 32 byte seed for the private key, expands it to
 * a full WOTS private key and computes the corresponding public key.
 * It requires the seed pub_seed (used to generate bitmasks and hash keys)
 * and the address of this WOTS key pair.
 *
 * Writes the computed public key to 'pk'.
 */

/*
 * Parameter wrapper for thread arguments
 * For function wots_pkgen_sub
 */
typedef struct wots_pkgen_args
{
    const xmss_params *params;     // Pointer to constant XMSS settting
    uint32_t *addr;                // Pointer to duplicate array of uint32_t addr[8]
    uint32_t start;                // Start of iteration
    uint32_t end;                  // End of iteration
    const unsigned char *pub_seed; // Pointer to constant public seed array
    unsigned char *pk;             // Write to output public key
    uint16_t padding16;            // Padding for 8-byte alignment
} wots_pkgen_args_t;

static void *wots_pkgen_sub(void *vars)
{
    wots_pkgen_args_t *args = vars;
    for (uint32_t i = args->start; i < args->end; i++)
    {
        set_chain_addr(args->addr, i);
        gen_chain(args->params, args->pk + i * (args->params->n), args->pk + i * (args->params->n),
                  0, args->params->wots_w - 1, args->pub_seed, args->addr);
    }
    return NULL;
}

void wots_pkgen_mp(const xmss_params *params,
                   unsigned char *pk, const unsigned char *seed,
                   const unsigned char *pub_seed, uint32_t addr[8])
{
    /* The WOTS+ private key is derived from the seed. */
    expand_seed(params, pk, seed);

    const uint32_t block = params->wots_len / NUM_CORES;
    const uint32_t remain = (params->wots_len % NUM_CORES);
    uint32_t thread_addr[THREAD_NUMBERS][8];
    pthread_t thread[THREAD_NUMBERS];
    wots_pkgen_args_t args[THREAD_NUMBERS];

    for (unsigned i = 0; i < THREAD_NUMBERS; i++)
    {
        memcpy(thread_addr[i], addr, sizeof(uint32_t) * 8);
        args[i].addr = thread_addr[i];
        args[i].params = params;
        args[i].pk = pk;
        args[i].pub_seed = pub_seed;

        if (i == NUM_CORES)
        {
            args[i].start = params->wots_len - remain;
            args[i].end = params->wots_len;
        }
        else
        {
            args[i].start = i * block;
            args[i].end = (i + 1) * block;
        }

        pthread_create(&thread[i], NULL, wots_pkgen_sub, (void *)&args[i]);
        /*
         * When in doubt, run this function to check thread correctness
         * wots_pkgen_sub(&args[j]);
         */
    }

    for (unsigned i = 0; i < THREAD_NUMBERS; i++)
    {
        pthread_join(thread[i], NULL);
    }
}

void wots_pkgen(const xmss_params *params,
                unsigned char *pk, const unsigned char *seed,
                const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;

    /* The WOTS+ private key is derived from the seed. */
    expand_seed(params, pk, seed);

    for (i = 0; i < params->wots_len; i++)
    {
        set_chain_addr(addr, i);
        gen_chain(params, pk + i * params->n, pk + i * params->n,
                  0, params->wots_w - 1, pub_seed, addr);
    }
}

/**
 * Takes a n-byte message and the 32-byte seed for the private key to compute a
 * signature that is placed at 'sig'.
 */

/*
 * Parameter wrapper for thread arguments
 * For function wots_sign_sub
 */
typedef struct wots_sign_args
{
    const xmss_params *params;     // Pointer to constant XMSS settting
    uint32_t *addr;                // Pointer to duplicate array of uint32_t addr[8]
    const unsigned char *pub_seed; // Pointer to constant public seed array
    unsigned char *sig;            // Write to output signature
    uint16_t padding16;            // Padding for 8-byte alignment
    int *lengths;                  // Pointer to length array
    uint32_t start;                // Start of iteration
    uint32_t end;                  // End of iteration
} wots_sign_args_t;

static void *wots_sign_sub(void *vars)
{
    wots_sign_args_t *args = vars;

    for (uint32_t i = args->start; i < args->end; i++)
    {
        set_chain_addr(args->addr, i);
        gen_chain(args->params, args->sig + i * args->params->n, args->sig + i * args->params->n,
                  0, args->lengths[i], args->pub_seed, args->addr);
    }
    return NULL;
}

void wots_sign_mp(const xmss_params *params,
                  unsigned char *sig, const unsigned char *msg,
                  const unsigned char *seed, const unsigned char *pub_seed,
                  uint32_t addr[8])
{
    int lengths[params->wots_len];
    chain_lengths(params, lengths, msg);
    /* The WOTS+ private key is derived from the seed. */
    expand_seed(params, sig, seed);

    const uint32_t block = params->wots_len / NUM_CORES;
    const uint32_t remain = (params->wots_len % NUM_CORES);
    pthread_t thread[THREAD_NUMBERS];
    uint32_t thread_addr[THREAD_NUMBERS][8];
    wots_sign_args_t args[THREAD_NUMBERS];

    for (unsigned i = 0; i < THREAD_NUMBERS; i++)
    {
        memcpy(thread_addr[i], addr, sizeof(uint32_t) * 8);
        args[i].addr = thread_addr[i];
        args[i].params = params;
        if (i == NUM_CORES)
        {
            args[i].start = params->wots_len - remain;
            args[i].end = params->wots_len;
        }
        else
        {
            args[i].start = i * block;
            args[i].end = (i + 1) * block;
        }
        args[i].sig = sig;
        args[i].lengths = lengths;
        args[i].pub_seed = pub_seed;

        pthread_create(&thread[i], NULL, wots_sign_sub, (void *)&args[i]);
        /*
         * When in doubt, run this function to check thread correctness
         * wots_sign_sub(&args[i]);
         */
    }

    for (unsigned i = 0; i < THREAD_NUMBERS; i++)
    {
        pthread_join(thread[i], NULL);
    }
}

void wots_sign(const xmss_params *params,
               unsigned char *sig, const unsigned char *msg,
               const unsigned char *seed, const unsigned char *pub_seed,
               uint32_t addr[8])
{
    int lengths[params->wots_len];
    uint32_t i;

    chain_lengths(params, lengths, msg);

    /* The WOTS+ private key is derived from the seed. */
    expand_seed(params, sig, seed);

    for (i = 0; i < params->wots_len; i++)
    {
        set_chain_addr(addr, i);
        gen_chain(params, sig + i * params->n, sig + i * params->n,
                  0, lengths[i], pub_seed, addr);
    }
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */

/*
 * Parameter wrapper for thread arguments
 * For function wots_pk_from_sig_sub
 */
typedef struct wots_pk_sig
{
    const xmss_params *params;     // Pointer to constant XMSS settting
    unsigned char *pk;             // Write to output public key
    const unsigned char *sig;      // Pointer to constant signature array
    const unsigned char *pub_seed; // Pointer to constant public seed array
    uint32_t *addr;                // Pointer to duplicate array of uint32_t addr[8]
    uint32_t start;                // Start of iteration
    uint32_t end;                  // End of iteration
    int *lengths;                  // Pointer to length array
} wots_pk_sig_t;

static void *wots_pk_from_sig_sub(void *vars)
{
    wots_pk_sig_t *args = vars;

    for (uint32_t i = args->start; i < args->end; i++)
    {
        set_chain_addr(args->addr, i);
        gen_chain(args->params, (args->pk) + i * (args->params->n), (args->sig) + i * (args->params->n),
                  args->lengths[i], (args->params->wots_w) - 1 - (args->lengths[i]), args->pub_seed, args->addr);
    }
    return NULL;
}

void wots_pk_from_sig_mp(const xmss_params *params, unsigned char *pk,
                         const unsigned char *sig, const unsigned char *msg,
                         const unsigned char *pub_seed, uint32_t addr[8])
{
    const uint32_t block = params->wots_len / NUM_CORES;
    const uint32_t remain = (params->wots_len % NUM_CORES);
    int lengths[params->wots_len];

    chain_lengths(params, lengths, msg);

    pthread_t thread[THREAD_NUMBERS];
    uint32_t thread_addr[THREAD_NUMBERS][8];
    wots_pk_sig_t args[THREAD_NUMBERS];

    for (unsigned i = 0; i < THREAD_NUMBERS; i++)
    {
        memcpy(thread_addr[i], addr, sizeof(uint32_t) * 8);
        args[i].addr = thread_addr[i];
        args[i].params = params;
        if (i == NUM_CORES)
        {
            args[i].start = params->wots_len - remain;
            args[i].end = params->wots_len;
        }
        else
        {
            args[i].start = i * block;
            args[i].end = (i + 1) * block;
        }
        args[i].sig = sig;
        args[i].pk = pk;
        args[i].lengths = lengths;
        args[i].pub_seed = pub_seed;

        pthread_create(&thread[i], NULL, wots_pk_from_sig_sub, (void *)&args[i]);
        /*
         * When in doubt, run this function to check thread correctness
         * wots_pk_from_sig_sub(&args[i]);
         */
    }

    for (unsigned i = 0; i < THREAD_NUMBERS; i++)
    {
        pthread_join(thread[i], NULL);
    }
}

void wots_pk_from_sig(const xmss_params *params, unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    int lengths[params->wots_len];
    uint32_t i;

    chain_lengths(params, lengths, msg);

    for (i = 0; i < params->wots_len; i++)
    {
        set_chain_addr(addr, i);
        gen_chain(params, pk + i * params->n, sig + i * params->n,
                  lengths[i], params->wots_w - 1 - lengths[i], pub_seed, addr);
    }
}
