#include <string.h>

#include "secret_key.h"
#include "params.h"

int (*oqs_save_updated_key)(OQS_SECRET_KEY *sk);

OQS_SECRET_KEY *OQS_SECRET_KEY_new(const char *method_name) {

    // Initialize the secret key in the heap with adequate memory
    OQS_SECRET_KEY *sk = malloc(sizeof(OQS_SECRET_KEY));
    if (sk == NULL) return NULL;
    
    // Convert the XMSS/XMSS^MT algorithm name to an OID
    xmss_str_to_oid(&sk->oid, method_name);

    // Convert the oid into a XMSS parameters list and extract the length of the secret key.
    xmss_params par;
    xmss_parse_oid(&par, sk->oid);
    sk->length_secret_key = par.sk_bytes;

    // Initialize the key with length_secret_key amount of bytes.
    sk->secret_key = malloc(sk->length_secret_key * sizeof(uint8_t));
}

void OQS_SECRET_KEY_free(OQS_SECRET_KEY *sk) {
    free(sk->secret_key);
}