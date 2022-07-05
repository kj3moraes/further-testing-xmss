#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../sig_stfl/sig_stfl.h"

#define XMSS_IMPLEMENTATION "XMSS-SHA2_16_256"
#define MAX_LENGTH_FILENAME 60

static void hexdump(uint8_t*d, unsigned int l) {
    for(unsigned int i=0; i<l ;i++) printf("%02x", d[i]);
    printf("\n");
}

void prepend(char* s, const char* t) {
    size_t len = strlen(t);
    memmove(s + len, s, strlen(s) + 1);
    memcpy(s, t, len);
}

/** =========== FUNCTIONS THAT GET ASSIGNED TO THE POINTERS IN THE OBJECT ===== */

int lock_sk_key(OQS_SECRET_KEY *sk) {
    return 0;
}

int release_sk_key(OQS_SECRET_KEY *sk) {
    return 0;
}

int do_nothing_save(OQS_SECRET_KEY *sk) {
    return 0;
}

int sk_file_write(OQS_SECRET_KEY *sk) {

    unsigned char filename[MAX_LENGTH_FILENAME] = "./keys/opps_xmss16_sha256.prv";

    #ifdef CUSTOM_NAME
        printf("\nEnter the filename that you want written to>");
        scanf("%32s", filename);
        strcat(filename, ".prv");
        prepend(filename, "./keys/")
    #endif

    printf("\nWriting to file %s\n", filename);

    #ifdef DEBUGGING
        unsigned long idx = ((unsigned long)sk->secret_key[XMSS_OID_LEN + 0] << 24) |
                        ((unsigned long)sk->secret_key[XMSS_OID_LEN + 1] << 16) |
                        ((unsigned long)sk->secret_key[XMSS_OID_LEN + 2] << 8) |
                        ((unsigned long)sk->secret_key[XMSS_OID_LEN + 3]);
        printf("The index (after the increment) is : %ld\n", idx);
    #endif

    FILE *printer = fopen(filename, "w+");
    if (printer == NULL) {
        perror("ERROR! There is no such file. Terminating...");
        return -1;
    }

    // Write the entire secret key byte array to the specified file.
    for (unsigned int i = 0; i < sk->length_secret_key; i++) {
        
        if (fputc(sk->secret_key[i], printer) == EOF) {
            perror("ERROR! There is no such file. Terminating...");
            return -1;
        }
    }
    fclose(printer);
    printf("Completed the write operation\n");
    return 0;
}

/** =========================================================================== */


int test_case(const char *name) {

    int ret = 0;
    unsigned int i;

    printf("\n\t===== Complete Testing %s ===== \n", name);
    
    // Defining the secret key
    OQS_SECRET_KEY *sk = OQS_SECRET_KEY_new(name);
    sk->lock_key = lock_sk_key;
    sk->release_key = release_sk_key;
    sk->oqs_save_updated_sk_key = sk_file_write;
    
    // Defining the stateful signature object
    OQS_SIG_STFL *signature_gen = OQS_SIG_STFL_new(name);

    // Standardized in the message so that we can check the output.
    const unsigned int MESSAGE_LENGTH = 32;
    uint8_t *m = (uint8_t *)malloc( MESSAGE_LENGTH);

    // Defining the rest of the data needed for singing and verifying.
    uint8_t *pk = (uint8_t *)malloc(signature_gen->length_public_key);
    uint8_t *sm = (uint8_t *)malloc(signature_gen->length_signature);
    unsigned long long smlen;
    unsigned char filename[MAX_LENGTH_FILENAME];


    OQS_randombytes(m, MESSAGE_LENGTH);
    printf("\nmsg="); hexdump(m, MESSAGE_LENGTH);

    printf("sk_bytes=%llu + oid\n", sk->length_secret_key);
    printf("pk_bytes=%llu + oid\n", signature_gen->length_public_key);
    printf("sig_bytes=%llu\n", signature_gen->length_signature);

    printf("Generating keys ...\n");
    signature_gen->keypair(pk, sk);

    unsigned int NUM_TESTS;
    printf("\nEnter the number of tests you want to run>");
    scanf("%u", &NUM_TESTS);
    
    printf("\n\n === Testing %d %s signatures.. === \n", NUM_TESTS, name);

    for (i = 0; i < NUM_TESTS; i++) {
        printf("\n\n=========  - iteration #%d: ==============\n", i);

        /* ========================== SIGNING ================================= */
        randombytes(m, MESSAGE_LENGTH);
        if (signature_gen->sign(sm, &smlen, m, MESSAGE_LENGTH, sk) != 0) {
            printf("ERROR!! Signature generation failed\n");
            ret = -1;
        }

        printf("\nsignature_length=%llu\n", smlen);
        printf("sm="); hexdump(sm, smlen);
        #ifdef DEBUGGING
            printf("\nnew_sk="); hexdump(sk->secret_key, sk->length_secret_key);
        #endif

        /* ===================== SIGNATURE LENGTH CHECK ======================= */
   

        if (smlen != signature_gen->length_signature) {
            printf("  X smlen incorrect [%llu != %u]!\n", smlen, signature_gen->length_signature);
            ret = -1;
        }
        else 
            printf("    smlen as expected [%llu].\n", smlen);
        

        /* ========================= VERIFICATION ============================= */


        ret = signature_gen->verify(m, MESSAGE_LENGTH, sm, smlen, pk);
        if (ret) {
            printf("  X verification failed!\n");
        }
        else {
            printf("    verification succeeded.\n");
        }

        if(ret) return ret;
    }

    OQS_SECRET_KEY_free(sk);
    OQS_SIG_STFL_free(signature_gen);
    free(m);
    free(sm);
    return 0;
}


int main() {
    int rc = test_case(XMSS_IMPLEMENTATION);
    if(rc != 0) return rc;
    return 0;
}