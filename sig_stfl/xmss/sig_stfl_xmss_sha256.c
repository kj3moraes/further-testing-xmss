
#include <stdlib.h>

#include "sig_stfl_xmss.h"

// #if defined(OQS_ENABLE_SIG_dilithium_2_aes)

OQS_SIG_STFL *OQS_SIG_STFL_xmss_sha256_h10() {
    
    OQS_SIG_STFL *sig = (OQS_SIG_STFL *)malloc(sizeof(OQS_SIG_STFL));
    if (sig == NULL) {
        return NULL;
    }
    sig->method_name = "XMSS-SHA2_10_256";
    sig->alg_version = "..."; 

    sig->claimed_nist_level = 2;
    sig->euf_cma = true;

    /*
    sig->length_public_key = OQS_SIG_STFL_alg_xmss_sha256_h10_length_public_key;
	sig->length_secret_key = OQS_SIG_STFL_alg_xmss_sha256_h10_length_secret_key;
	sig->length_signature = OQS_SIG_STFL_alg_xmss_sha256_h10_length_signature;
    */

    sig->keypair = OQS_SIG_STFL_alg_xmss_sha256_h10_keypair;
    sig->sign = OQS_SIG_STFL_alg_xmss_sha256_h10_sign;
    sig->verify = OQS_SIG_STFL_alg_xmss_sha256_h10_verify;

    return sig;
}


// #endif