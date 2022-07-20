#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../sig_stfl/sig_stfl.h"
#include "../sig_stfl/xmss/external/randombytes.h"

#define XMSS_IMPLEMENTATION "XMSS-SHA2_16_256"
#define MAX_LENGTH_FILENAME 60
#define NUM_SUBKEYS 3

static void hexdump(const uint8_t *d, const unsigned long long l) {
    printf("length=%llu\n", l);
    for(unsigned long long i=0; i<l ;i++) {
        if (i % 16 == 0) printf("\n");
        printf("%02x", d[i]);
    }
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

int sk_file_write(const OQS_SECRET_KEY *sk) {

    char filename[MAX_LENGTH_FILENAME];
    strcpy(filename, "./keys/opps_xmss16_sha256.prv");

    #ifdef CUSTOM_NAME
        printf("\nEnter the filename that you want written to>");
        scanf("%32s", filename);
        strcat(filename, ".prv");
        prepend(filename, "./keys/")
    #endif

    printf("\nWriting to file %s\n", filename);
    FILE *printer = fopen(filename, "w+");
    if (printer == NULL) {
        perror("ERROR! There is no such file. Terminating...");
        return -1;
    }

    // Write the entire secret key byte array to the specified file.
    for (unsigned long i = 0; i < sk->length_secret_key; i++) {
        
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

    printf("\n\t===== Subkey Testing %s ===== \n\n\n", name);
    
    // Defining the secret key
    OQS_SECRET_KEY *master_key = OQS_SECRET_KEY_new(name);
    master_key->lock_key = lock_sk_key;
    master_key->release_key = release_sk_key;
    master_key->oqs_save_updated_sk_key = sk_file_write;

    // Defining all the subkeys
    OQS_SECRET_KEY *subkeys[NUM_SUBKEYS];
    
    // Defining the stateful signature object
    OQS_SIG_STFL *signature_gen = OQS_SIG_STFL_new(name);

    // Standardized in the message so that we can check the output.
    const unsigned int MESSAGE_LENGTH = 32;
    uint8_t *m = (uint8_t *)malloc( MESSAGE_LENGTH);

    // Defining the rest of the data needed for singing and verifying.
    uint8_t *pk = (uint8_t *)malloc(signature_gen->length_public_key);
    uint8_t *sm = (uint8_t *)malloc(signature_gen->length_signature);
    unsigned long long smlen = 0;

    OQS_randombytes(m, MESSAGE_LENGTH);

    printf("==== BOOK KEEPING INFORMATION =====\n");
    printf("\nmsg="); hexdump(m, MESSAGE_LENGTH);
    printf("sk_bytes=%llu + oid\n", (unsigned long long)master_key->length_secret_key);
    printf("pk_bytes=%llu\n", (unsigned long long)signature_gen->length_public_key);
    printf("sig_bytes=%llu\n", (unsigned long long)signature_gen->length_signature);

    unsigned int decision;
    char filename[MAX_LENGTH_FILENAME];
    printf("\nDo you want to generate a new key? (1/0)>");
    scanf("%d", &decision);

    if (decision == 1) {
        printf("Generating keys ...\n");
        signature_gen->keypair(pk, master_key);
        printf("\nGenerated a new key\n");

        printf("\nDo you want to save the key? (1/0)>");
        scanf("%d", &decision);

        if (decision == 1) {
            printf("Saving the key ...\n");
            
            printf("\nEnter the filename that you want written to>");
            scanf("%32s", filename);

            prepend(filename, "./keys/");

            FILE *pub_key = fopen(strcat(filename, ".pub"), "w+");
            for (unsigned int i = 0; i < signature_gen->length_public_key; i++) {
                fputc(pk[i], pub_key);
            }
            fclose(pub_key);

            // Changing the .pub extension to .prv
            filename[strlen(filename) - 2] = 'r'; filename[strlen(filename) - 1] = 'v';
            FILE *prv_key = fopen(filename, "w+");
            for (unsigned int i = 0; i < master_key->length_secret_key; i++) {
                fputc(master_key->secret_key[i], prv_key);
            }
            fclose(prv_key);
            printf("\nSaved the key\n");
        }

    } else {
        printf("\nUsing the existing key...\n");

        printf("\nEnter the filestem that you want read from>");
        scanf("%32s", filename);
        prepend(filename, "./keys/");

        // Public Key
        strcat(filename, ".pub");
        FILE *reader = fopen(filename, "rb");
        if (reader == NULL) {
            perror("ERROR! There is no such file. Terminating...");
            return -1;
        }
        for (i = 0; i < signature_gen->length_public_key; i++) {
            pk[i] = fgetc(reader);
        }
        fclose(reader);

        // Private Key
        filename[strlen(filename) - 2] = 'r'; filename[strlen(filename) - 1] = 'v';
        printf("\nReading from file %s\n", filename);
        reader = fopen(filename, "rb");
        if (reader == NULL) {
            perror("ERROR! There is no such file. Terminating...");
            return -1;
        }
        for (i = 0; i < master_key->length_secret_key; i++) {
            master_key->secret_key[i] = fgetc(reader);
        }
        fclose(reader);
    }  
    
    printf("\nPublic key="); hexdump(pk, signature_gen->length_public_key);
    printf("\nSecret key="); hexdump(master_key->secret_key, master_key->length_secret_key);

    printf("\n\n === Generating %d %s subkeys... === \n", NUM_SUBKEYS, name);
    for (i = 0; i < NUM_SUBKEYS; i++) {
        
        unsigned long long number_sigs = 0;
        printf("\nEnter the number of signatures to be generated for subkey %d>", i);
        scanf("%llu", &number_sigs);

        subkeys[i] = OQS_SECRET_KEY_derive_subkey(master_key, number_sigs);

        printf("\nsubkey %d:=", i + 1);
        hexdump(subkeys[i]->secret_key, subkeys[i]->length_secret_key);
        printf("\n");

        printf("\nmaster key after %d^th subkey:=", i + 1);
        hexdump(subkeys[i]->secret_key, subkeys[i]->length_secret_key);
        printf("\n");

        subkeys[i]->lock_key = lock_sk_key;
        subkeys[i]->release_key = release_sk_key;
        subkeys[i]->oqs_save_updated_sk_key = sk_file_write;
    }
    return 0;    

    printf("Do you want to test? (1/0)>");
    scanf("%d", &decision);
    if (decision == 0) return -1;

    unsigned int NUM_TESTS;
    printf("\nEnter the number of tests you want to run>");
    scanf("%u", &NUM_TESTS);
    
    printf("\n\n === Testing signatures for %d %s subkeys + master key testing.. === \n", NUM_SUBKEYS, name);

    for (i = 0; i < NUM_SUBKEYS; i++) {
        printf("\n\n=========  - iteration #%d: ==============\n", i);

        /* ========================== SIGNING ================================= */
        randombytes(m, MESSAGE_LENGTH);
        if (signature_gen->sign(sm, (size_t *)&smlen, m, MESSAGE_LENGTH, master_key) != 0) {
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
            printf("  X smlen incorrect [%llu != %u]!\n", smlen, (unsigned int)signature_gen->length_signature);
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

    OQS_SECRET_KEY_free(master_key);
    for (i = 0; i < NUM_SUBKEYS; i++) {
        OQS_SECRET_KEY_free(subkeys[i]);
    }
    OQS_SIG_STFL_free(signature_gen);
    free(m);
    free(pk);
    free(sm);
    return 0;
}


int main() {
    int rc = test_case(XMSS_IMPLEMENTATION);
    if(rc != 0) return rc;
    return 0;
}