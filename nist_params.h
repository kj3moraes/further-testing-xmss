/*=============================================================================
 * Copyright (c) 2022 by SandboxAQ Inc
 * Author: Duc Tri Nguyen
 * SPDX-License-Identifier: MIT
=============================================================================*/
#ifndef NIST_PARAM_H
#define NIST_PARAM_H

#include "params.h"

#ifndef XMSSMT
#define XMSSMT 0
#endif

#ifndef LEVEL
#define LEVEL 0
#endif

#ifndef RANDOM
#define RANDOM 1
#endif

#ifndef POSIX_THREAD
#define POSIX_THREAD 1
#endif

#if XMSSMT == 0
    /* 
    * Maximum signatures: 2^h = 2^10
    */
    #if LEVEL == 0

    #define XMSS_OID "XMSS-SHA2_10_256"

    #define XMSS_PUBLICKEYBYTES 64
    #define XMSS_SECRETKEYBYTES 2045

    #define XMSS_SIGNBYTES 2500

    /* 
    * Maximum signatures: 2^h = 2^16
    */
    #elif LEVEL == 1

    #define XMSS_OID "XMSS-SHA2_16_256"

    #define XMSS_PUBLICKEYBYTES 64
    #define XMSS_SECRETKEYBYTES 3149

    #define XMSS_SIGNBYTES 2692

    /* 
    * Maximum signatures: 2^h = 2^20
    */
    #elif LEVEL == 2

    #define XMSS_OID "XMSS-SHA2_20_256"

    #define XMSS_PUBLICKEYBYTES 64
    #define XMSS_SECRETKEYBYTES 3885

    #define XMSS_SIGNBYTES 2820


    #else

    #error "Unspecified LEVEL {0,1,2}"

    #endif
#else 
    /* 
    * Maximum signatures: 2^h = 2^20
    * XMSS^MT has bigger signature and secret key (secret is not transfer), but better speed
    */
    #if LEVEL == 0

    #define XMSS_OID "XMSSMT-SHA2_20/2_256"

    #define XMSS_PUBLICKEYBYTES 64
    #define XMSS_SECRETKEYBYTES 8078

    #define XMSS_SIGNBYTES 4963

    /* 
    * Maximum signatures: 2^h = 2^40
    * XMSS^MT has bigger signature and secret key (secret is not transfer), but better speed
    */
    #elif LEVEL == 1

    #define XMSS_OID "XMSSMT-SHA2_40/2_256"

    #define XMSS_PUBLICKEYBYTES 64
    #define XMSS_SECRETKEYBYTES 13600

    #define XMSS_SIGNBYTES 5605

    /* 
    * Maximum signatures: 2^h = 2^60
    * XMSS^MT has bigger signature and secret key (secret is not transfer), but better speed
    */
    #elif LEVEL == 2

    #define XMSS_OID "XMSSMT-SHA2_60/3_256"

    #define XMSS_PUBLICKEYBYTES 64
    #define XMSS_SECRETKEYBYTES 23317

    #define XMSS_SIGNBYTES 8392


    #else

    #error "Unspecified LEVEL {0,1,2}"

    #endif

#endif

#if XMSSMT == 1
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_KEYPAIR xmssmt_keypair
    #define XMSS_SIGN xmssmt_sign
    #define XMSS_SIGN_OPEN xmssmt_sign_open
    #define XMSS_REMAINING_SIG xmssmt_remaining_signatures

    #define XMSS_KEYPAIR_MP xmssmt_keypair_mp
    #define XMSS_SIGN_MP xmssmt_sign_mp
    #define XMSS_SIGN_OPEN_MP xmssmt_sign_open_mp
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_KEYPAIR xmss_keypair
    #define XMSS_SIGN xmss_sign
    #define XMSS_SIGN_OPEN xmss_sign_open
    #define XMSS_REMAINING_SIG xmss_remaining_signatures

    #define XMSS_KEYPAIR_MP xmss_keypair_mp
    #define XMSS_SIGN_MP xmss_sign_mp
    #define XMSS_SIGN_OPEN_MP xmss_sign_open_mp
#endif

#define CRYPTO_PUBLIC_KEY (XMSS_PUBLICKEYBYTES + XMSS_OID_LEN)
#define CRYPTO_SECRET_KEY (XMSS_SECRETKEYBYTES + XMSS_OID_LEN)
#define CRYPTO_BYTES XMSS_SIGNBYTES

#endif
