#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "utils.h"
#include "hash.h"
#include "wots.h"
#include "hash_address.h"
#include "params.h"
#include <pthread.h>

/**
 * Helper method for pseudorandom key generation.
 * Expands an n-byte array into a len*n byte array using the `prf` function.
 */
static void expand_seed(const xmss_params *params,
                        unsigned char *outseeds, const unsigned char *inseed)
{
    uint32_t i;
    unsigned char ctr[32];

    for (i = 0; i < params->wots_len; i++) {
        ull_to_bytes(ctr, 32, i);
        prf(params, outseeds + i*params->n, ctr, inseed);
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
    for (i = start; i < (start+steps) && i < params->wots_w; i++) {
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

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
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
    for (i = 0; i < params->wots_len1; i++) {
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
#define NUM_CORES 4
#define DEBUG 0

typedef struct wots_pkgen_args
{
    const xmss_params *params;
    const unsigned char *pub_seed;
    unsigned char *pk;
    unsigned char *none;
    unsigned char *none1;
    uint32_t bla; 
    uint32_t *addr;
    unsigned int start; 
    unsigned int end;
    unsigned int num;
} wots_pkgen_args_t;

void *wots_pkgen_sub(void *arg)
{
    wots_pkgen_args_t *args = arg;
    for (unsigned i = args->start; i < args->end; i++)
    {
        set_chain_addr(args->addr, i);
        gen_chain(args->params, args->pk + i*(args->params->n), args->pk + i*(args->params->n),
                0, args->params->wots_w - 1, args->pub_seed, args->addr);
    }
#if DEBUG
    printf("%d: ", args->num);
    for (int i = 0; i < 8; i++)
    {
        printf("%02x", args->addr[i]);
    }
    printf("\n");
#endif
    return NULL;
}

void wots_pkgen(const xmss_params *params,
                unsigned char *pk, const unsigned char *seed,
                const unsigned char *pub_seed, uint32_t addr[8])
{
    const uint32_t length = params->wots_len/NUM_CORES;
    const uint32_t leftover = params->wots_len % NUM_CORES; 

    /* The WOTS+ private key is derived from the seed. */
    expand_seed(params, pk, seed);
    uint32_t thread_addr[NUM_CORES + 1][8];
    
    pthread_t thread[NUM_CORES + 1]; 

    for (int j = 0; j < NUM_CORES + 1; j++)
    {
        memcpy(thread_addr[j], addr, sizeof(uint32_t) * 8);
    }

    wots_pkgen_args_t args[NUM_CORES + 1]; 

    for (int j = NUM_CORES; j >= 0; j--)
    {
        args[j].addr = thread_addr[j]; 
        args[j].params = params; 
        args[j].pk = pk;
        args[j].pub_seed = pub_seed; 
        if (j == NUM_CORES)
        {
            args[j].start = params->wots_len - leftover; 
            args[j].end = params->wots_len;    
        }
        else
        {
            args[j].start = j*length; 
            args[j].end = (j+1)*length;
        }
        args[j].num = j;
        
        int status = pthread_create(&thread[j], NULL, wots_pkgen_sub, (void *) &args[j]);
        if (status != 0) printf("status = %d\n", status);

        // wots_pkgen_sub(&args[j]);
    }
    
    for (int j = 0; j < NUM_CORES + 1; j++) 
    {
        pthread_join(thread[j], NULL);
    }
}


// void wots_pkgen(const xmss_params *params,
//                 unsigned char *pk, const unsigned char *seed,
//                 const unsigned char *pub_seed, uint32_t addr[8])
// {
//     uint32_t i;

//     /* The WOTS+ private key is derived from the seed. */
//     expand_seed(params, pk, seed);

//     for (i = 0; i < params->wots_len; i++) {
//         // Lock address 
//         set_chain_addr(addr, i);
//         // This ready to go after lock `addr` variable
//         gen_chain(params, pk + i*params->n, pk + i*params->n,
//                   0, params->wots_w - 1, pub_seed, addr);
//     } 

    // uint32_t thread_addr[NUM_CORES][8];


    // uint32_t length = params->wots_len/NUM_CORES;
    // uint32_t leftover = params->wots_len % NUM_CORES; 

    // for (i = 0; i < leftover; i++)
    // {
    //     set_chain_addr(addr, i);
    //     gen_chain(params, pk + i*params->n, pk + i*params->n,
    //               0, params->wots_w - 1, pub_seed, addr);
    // }

    // for (int j = 0; j < NUM_CORES; j++)
    // {
    //     // memcpy(thread_addr[j], addr, sizeof(uint32_t) * 8);
    //     for (int k = 0; k < 8; k++)
    //     {
    //         thread_addr[j][k] = addr[k];
    //     }
    // }

    // for (; i < leftover + length; i++)
    // {
    //     // 1st thread
    //     set_chain_addr(thread_addr[0], i);
    //     gen_chain(params, pk + i*params->n, pk + i*params->n,
    //               0, params->wots_w - 1, pub_seed, addr);
    // }

    // for (; i < leftover + 2*length; i++)
    // {
    //     set_chain_addr(thread_addr[1], i);
    //     gen_chain(params, pk + i*params->n, pk + i*params->n,
    //               0, params->wots_w - 1, pub_seed, addr);
    // }

    // for (; i < leftover + 3*length; i++)
    // {
    //     set_chain_addr(thread_addr[2], i);
    //     gen_chain(params, pk + i*params->n, pk + i*params->n,
    //               0, params->wots_w - 1, pub_seed, addr);
    // }

    // for (; i < leftover + 4*length; i++)
    // {
    //     set_chain_addr(thread_addr[3], i);
    //     gen_chain(params, pk + i*params->n, pk + i*params->n,
    //               0, params->wots_w - 1, pub_seed, addr);
    // }
    // printf("i = %d, %d\n", i, params->wots_len);
// }

/**
 * Takes a n-byte message and the 32-byte seed for the private key to compute a
 * signature that is placed at 'sig'.
 */
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

    for (i = 0; i < params->wots_len; i++) {
        set_chain_addr(addr, i);
        gen_chain(params, sig + i*params->n, sig + i*params->n,
                  0, lengths[i], pub_seed, addr);
    }
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig(const xmss_params *params, unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    int lengths[params->wots_len];
    uint32_t i;

    chain_lengths(params, lengths, msg);

    for (i = 0; i < params->wots_len; i++) {
        set_chain_addr(addr, i);
        gen_chain(params, pk + i*params->n, sig + i*params->n,
                  lengths[i], params->wots_w - 1 - lengths[i], pub_seed, addr);
    }
}
