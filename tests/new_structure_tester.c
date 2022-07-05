#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../sig_stfl/sig_stfl.h"

#define XMSS_IMPLEMENTATION "XMSS-SHA2_16_256"
#define XMSS_MLEN 32
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


int test_case(const char *name, int xmssmt) {

    int ret = 0;
    unsigned int i;

    printf("\n\t===== Complete Testing %s ===== \n", name);
    OQS_SIG_STFL *signature_gen = OQS_SIG_STFL_new(name);


    
    // Defining the secret key
    OQS_SECRET_KEY *sk = OQS_SECRET_KEY_new(name);
    sk->lock_key = lock_sk_key;
    sk->release_key = release_sk_key;
    sk->oqs_save_updated_sk_key = sk_file_write;

    // Standardized in the message so that we can check the output.
    unsigned char *m = (unsigned char*)malloc(XMSS_MLEN);
    // for (i = 0; i < XMSS_MLEN; i++) m[i] = i;
    
    unsigned char *sm = (unsigned char*)malloc(params.sig_bytes + XMSS_MLEN);
    unsigned char *mout = (unsigned char*)malloc(params.sig_bytes + XMSS_MLEN);
    unsigned long long smlen;
    unsigned char filename[MAX_LENGTH_FILENAME];

    OQS_randombytes(m, XMSS_MLEN);
    printf("\nmsg="); hexdump(m, XMSS_MLEN);

    printf("sk_bytes=%llu + oid\n", params.sk_bytes);

    unsigned int decision;
    printf("Do you want to generate keys (0) or use stored ones (1) ? >");
    scanf("%d", &decision);
    return 0;
}


int main() {
    int rc = test_case(XMSS_IMPLEMENTATION, 0);
    if(rc != 0) return rc;
    return 0;
}