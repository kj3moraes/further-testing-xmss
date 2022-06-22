#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../xmss.h"
#include "../params.h"
#include "../randombytes.h"

#define XMSS_IMPLEMENTATION "XMSS-SHA2_20_256"
#define XMSS_MLEN 32
#define NUM_TESTS 100
#define MAX_LENGTH_FILENAME 60

static void hexdump(unsigned char *d, unsigned int l) {
    for(unsigned int i=0; i<l ;i++) printf("%02x", d[i]);
    printf("\n");
}

void prepend(char* s, const char* t) {
    size_t len = strlen(t);
    memmove(s + len, s, strlen(s) + 1);
    memcpy(s, t, len);
}

/** =========== FUNCTIONS THAT GET ASSIGNED TO THE POINTERS IN THE OBJECT ===== */

int lock_sk_key(void) {
    return 0;
}

int release_sk_key(void) {
    return 0;
}

int do_nothing_save(void) {
    return 0;
}

/** =========================================================================== */


int test_case(const char *name, int xmssmt){
    xmss_params params;
    uint32_t oid;
    int ret = 0;
    unsigned int i;

    if(xmssmt){
        ret  = xmssmt_str_to_oid(&oid, name);
        ret |= xmssmt_parse_oid(&params, oid);
        if(ret) {
          printf("Invalid XMSSMT parameter string, exiting.\n");
          return -1;
        }
    }
    else {
        ret  = xmss_str_to_oid(&oid, name);
        ret |= xmss_parse_oid(&params, oid);
        if(ret) {
          printf("Invalid XMSS parameter string, exiting.\n");
          return -1;
        }
    }

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
    unsigned char *m = (unsigned char*)malloc(XMSS_MLEN);
    unsigned char *sm = (unsigned char*)malloc(params.sig_bytes + XMSS_MLEN);
    unsigned char *mout = (unsigned char*)malloc(params.sig_bytes + XMSS_MLEN);
    unsigned long long smlen, mlen;
    unsigned char filename[MAX_LENGTH_FILENAME];
    randombytes(m, XMSS_MLEN);

    printf("sk_bytes=%llu + oid\n", params.sk_bytes);

    unsigned int decision;
    printf("Do you want to generate keys (0) or use stored ones (1) ? >");
    scanf("%d", &decision);

    
    if (decision == 0) {

        /* === GENERATING KEYS AND THEN STORING THEM === */

        printf("Generating keys ....\n");
        if(xmssmt){
            xmssmt_keypair(pk, sk, oid);
        }
        else {
            xmss_keypair(pk, sk, oid);
        }

        // Receiving the filestem and then storing it in the keys folder.
        printf("Enter the filestem that you want written to>");
        scanf("%32s", filename);
        prepend(filename, "./keys/");

        FILE *pub_key = fopen(strcat(filename, ".pub"), "w+");
        for (unsigned int i = 0; i < XMSS_OID_LEN + params.pk_bytes; i++) {
            fputc(pk[i], pub_key);
        }
        fclose(pub_key);

        // Changing the .pub extension to .prv
        filename[strlen(filename) - 2] = 'r'; filename[strlen(filename) - 1] = 'v';
        FILE *prv_key = fopen(filename, "w+");
        for (unsigned int i = 0; i < XMSS_OID_LEN + params.sk_bytes; i++) {
            fputc(sk[i], prv_key);
        }
        fclose(prv_key);

        
    } else {

        /* === ACCESSING STORED KEYS === */

        printf("Enter the filestem where the keys are saved> ");
        scanf("%32s", filename);
        prepend(filename, "./keys/");   
        
        FILE *pub_key = fopen(strcat(filename, ".pub"), "rb");
        if (pub_key == NULL) return -1;
        for (unsigned int i = 0; i < params.pk_bytes + XMSS_OID_LEN; i++) {
            pk[i] = fgetc(pub_key);
        }
        fclose(pub_key);

        // Changing the .pub extension to .prv
        filename[strlen(filename) - 2] = 'r'; filename[strlen(filename) - 1] = 'v';

        printf("Reading in the secret key := \n");
        FILE *prv_key = fopen(filename, "rb");
        if (prv_key == NULL) return -1;
        for (unsigned int i = 0; i < params.sk_bytes + XMSS_OID_LEN; i++) {
            sk[i] = fgetc(prv_key);
            printf("%02x", sk[i]);
        }
        fclose(prv_key);
        printf("\n");

    }


    printf("pk="); hexdump(pk, sizeof pk);
    printf("sk="); hexdump(sk, sizeof sk);
    printf("Testing %d %s signatures.. \n", NUM_TESTS, name);

    for (i = 0; i < NUM_TESTS; i++) {
        printf("  - iteration #%d:\n", i);

        /* ========================== SIGNING ================================= */


        if(xmssmt){
            ret = xmssmt_sign(sk, sm, &smlen, m, XMSS_MLEN);
            if(i >= ((1ULL << params.full_height)-1)) {
                printf("here\n");
                if(ret != -2) {
                    printf("Error detecting running out of OTS keys\n");
                }
                else {
                    printf("Successfully detected running out of OTS keys\n");
                    return 0;
                }
            }
        }
        else {
            ret = xmss_sign(sk, sm, &smlen, m, XMSS_MLEN);
            if(i >= ((1ULL << params.tree_height)-1)) {
                if(ret != -2) {
                    printf("Error detecting running out of OTS keys\n");
                }
                else {
                    printf("Successfully detected running out of OTS keys\n");
                    return 0;
                }
            }
        }

        printf("sm="); hexdump(sm, smlen);


        /* ===================== PRELIMINARY CHECKS ========================== */
   

        if (smlen != params.sig_bytes + XMSS_MLEN) {
            printf("  X smlen incorrect [%llu != %u]!\n", smlen, params.sig_bytes);
            ret = -1;
        }
        else 
            printf("    smlen as expected [%llu].\n", smlen);
        

        /* ========================= VERIFICATION ============================= */


        if(xmssmt){
            ret = xmssmt_sign_open(mout, &mlen, sm, smlen, pk);
        }
        else {
            ret = xmss_sign_open(mout, &mlen, sm, smlen, pk);
        }
        if (ret) {
            printf("  X verification failed!\n");
        }
        else {
            printf("    verification succeeded.\n");
        }

        /* Test if the correct message was recovered. */
        if (mlen != XMSS_MLEN) {
            printf("  X mlen incorrect [%llu != %u]!\n", mlen, XMSS_MLEN);
            ret = -1;
        }
        else {
            printf("    mlen as expected [%llu].\n", mlen);
        }
        if (memcmp(m, mout, XMSS_MLEN)) {
            printf("  X output message incorrect!\n");
            ret = -1;
        }
        else {
            printf("    output message as expected.\n");
        }

        if(ret) return ret;
    }

    free(m);
    free(sm);
    free(mout);
    return 0;
}

int main()
{
    int rc;
    rc = test_case(XMSS_IMPLEMENTATION, 0);
    if(rc) return rc;
    return 0;
}
