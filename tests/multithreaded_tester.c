#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../sig_stfl/xmss/external/params.h"
#include "../sig_stfl/xmss/external/randombytes.h"
#include "../sig_stfl/xmss/external/xmss.h"

// Algorithm parameters
#define XMSS_IMPLEMENTATION "XMSS-SHA2_10_256"
#define XMSS_MLEN 32

// Testing parameters
#define NUM_TESTS 10
#define NUM_THREADS 2
#define MAX_LENGTH_FILENAME 60

pthread_mutex_t mutex;

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
    pthread_mutex_lock(&mutex);
    return 0;
}

int release_sk_key(OQS_SECRET_KEY *sk) {
    pthread_mutex_unlock(&mutex);
    return 0;
}

int do_nothing_save(OQS_SECRET_KEY *sk) {
    return 0;
}

int sk_file_write(OQS_SECRET_KEY *sk) {

    unsigned char filename[MAX_LENGTH_FILENAME] = "./keys/sink_xmss20_sha256.prv";

    #ifdef CUSTOM_NAME
    printf("\nEnter the filename that you want written to>");
    scanf("%32s", filename);
    strcat(filename, ".prv");
    prepend(filename, "./keys/")
    #endif

    printf("\nWriting to file %s\n", filename);

    unsigned long idx = ((unsigned long)sk->secret_key[XMSS_OID_LEN + 0] << 24) |
                        ((unsigned long)sk->secret_key[XMSS_OID_LEN + 1] << 16) |
                        ((unsigned long)sk->secret_key[XMSS_OID_LEN + 2] << 8) |
                        ((unsigned long)sk->secret_key[XMSS_OID_LEN + 3]);

    #ifdef DEBUGGING
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

        #ifdef DEBUGGING
        // printf("Byte being put: %02x\n", sk->secret_key[i]);
        #endif
    }
    fclose(printer);
    printf("Completed the write operation\n");
    return 0;
}

/** =========================================================================== */


/** ================= WRAPPER FUNCTIONS FOR MULTITHREADING ==================== */

struct signing_params {
    OQS_SECRET_KEY *sk;
    unsigned char *signature;
    unsigned int signature_length;
    unsigned char *message;
    unsigned int message_length;
};

struct verif_params {
    unsigned char *message;
    unsigned int message_length;
    unsigned char *signature;
    unsigned int signature_length;
    unsigned char *pk;
};



void *multi_xmss_sign(void *arg) {

    struct signing_params *params = (struct signing_params *)arg;

    for (unsigned int i = 0; i < NUM_TESTS; i++) {
        if (xmss_sign(params->sk, params->signature, params->signature_length, params->message, params->message_length) != 0) {
            printf("\nERROR! Signature failed\n");
            return NULL;
        }
    }
    return NULL;
}

void *multi_xmss_sign_open(void *arg) {

    struct verif_params *params = (struct verif_params *)arg;
    
    for (unsigned int i = 0; i < NUM_TESTS; i++) {
        if (xmss_sign_open(params->message, params->message_length, params->signature, params->signature_length, params->pk) != 0) {
            printf("\nERROR! Verification failed\n");
            return NULL;
        }
    }
    return NULL;
}


void *multi_xmssmt_sign(void *arg) {

    struct signing_params *params = (struct signing_params *)arg;

    for (unsigned int i = 0; i < NUM_TESTS; i++) {
        if (xmssmt_sign(params->sk, params->signature, params->signature_length, params->message, params->message_length) != 0) {
            printf("\nERROR! Signing failed\n");
            return NULL;
        }
    }
    return NULL;
}

void *multi_xmssmt_sign_open(void *arg) {

    struct verif_params *params = (struct verif_params *)arg;
    
    for (unsigned int i = 0; i < NUM_TESTS; i++) {
        if (xmssmt_sign_open(params->message, params->message_length, params->signature, params->signature_length, params->pk) != 0) {
            printf("\nERROR! Verification failed\n");
            return NULL;
        }
    }
    return NULL;
}


/** =========================================================================== */


int test_case(const char *name, int xmssmt) {
    xmss_params params;
    uint32_t oid;
    int ret = 0;
    unsigned int i;

    printf("\n\t===== Multithreaded Testing %s ===== \n", name);
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
    
    // Defining the secret key
    OQS_SECRET_KEY *sk = OQS_SECRET_KEY_new(name);
    sk->lock_key = lock_sk_key;
    sk->release_key = release_sk_key;
    sk->oqs_save_updated_sk_key = do_nothing_save;

    // Standardized in the message so that we can check the output.
    unsigned char *m = (unsigned char*)malloc(XMSS_MLEN);

    unsigned char *sm = (unsigned char*)malloc(params.sig_bytes + XMSS_MLEN);
    unsigned char *mout = (unsigned char*)malloc(params.sig_bytes + XMSS_MLEN);
    unsigned long long smlen, message_length = XMSS_MLEN;
    unsigned char filename[MAX_LENGTH_FILENAME];

    randombytes(m, XMSS_MLEN);
    printf("\nmsg="); hexdump(m, XMSS_MLEN);

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
        for (unsigned int i = 0; i < sk->length_secret_key; i++) {
            fputc(sk->secret_key[i], prv_key);
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
        for (unsigned int i = 0; i < sk->length_secret_key; i++) {
            sk->secret_key[i] = fgetc(prv_key);

            #ifdef DEBUGGING
                printf("%02x", sk->secret_key[i]);
            #endif
        }
        fclose(prv_key);
        printf("\n");

    }

    #ifdef DEBUGGING
        // Print out the public key, secret key as part of the debugging process
        printf("pk="); hexdump(pk, sizeof pk); printf("\n");
        printf("sk="); hexdump(sk->secret_key, sk->length_secret_key); printf("\n");
        
        printf("Continue (0 - no, 1 - yes) ? >");
        scanf("%d", &decision);
        if (decision == 0) return -1;   
    #endif


    #ifdef MAX_MOD
        // Change the max field of the secret key as part of the debugging process
        unsigned long long number_of_sigs;
        printf("Enter the max no. of the signatures >");
        scanf("%llu", &number_of_sigs);

        if (xmss_modify_maximum(sk, number_of_sigs) != 0) {
            printf("\nError in modifying the maximum number of signatures\n");
            return -1;
        }
        printf("\nnew_sk(post modify)="); hexdump(sk->secret_key, sk->length_secret_key); printf("\n");
    #endif

    pthread_t threads[NUM_THREADS];
    pthread_mutex_init(&mutex, NULL);

    printf("Testing %d %s signatures.. \n", NUM_TESTS, name);
    for (i = 0; i < NUM_TESTS; i++) {
        printf("\n\n=========  - iteration #%d: ==============\n", i);

        /* ========================== SIGNING ================================= */

        randombytes(m, XMSS_MLEN);
        struct signing_params sgpar  = {sk, sm, smlen, m, message_length};
        // sgpar.sk = sk;
        
        struct verif_params vfpar = {m, message_length, sm, smlen, pk};

        if(xmssmt){

            // SIGNING IN A MULTITHREADED WAY
            for (i = 0; i < NUM_THREADS; i++) {
                // Create the threads and run the xmssmt_sign function (multithreaded)
                if (pthread_create(&threads[i], NULL, multi_xmssmt_sign, (void*)&sgpar) != 0) {
                    printf("Error creating thread\n");
                    return -1;
                }
            }

            // WAITING FOR ALL THE SIGNING TO COMPLETE
            for (i = 0; i < NUM_THREADS; i++) {
                if (pthread_join(threads[i], NULL) != 0) {
                    printf("Error joining thread\n");
                    return -1;
                }

            }

            // VERIFYING IN A MULTITHREADED WAY
            for (i = 0; i < NUM_THREADS; i++) {
                // Create the threads and run the xmssmt_sign_open function (multithreaded)
                if (pthread_create(&threads[i], NULL, multi_xmssmt_sign_open, (void*)&vfpar) != 0) {
                    printf("Error creating thread\n");
                    return -1;
                }
            }
           
            // WAITING FOR ALL THE VERIFICATIONS TO COMPLETE
            for (i = 0; i < NUM_THREADS; i++) {
                if (pthread_join(threads[i], NULL) != 0) {
                    printf("Error joining thread\n");
                    return -1;
                }
            }

            if (i >= ((1ULL << params.full_height)-1)) {
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
            
            // SIGNING IN A MULTITHREADED WAY
            for (i = 0; i < NUM_THREADS; i++) {
                // Create the threads and run the xmssmt_sign function (multithreaded)
                if (pthread_create(&threads[i], NULL, multi_xmss_sign, (void*)&sgpar) != 0) {
                    printf("Error creating thread\n");
                    return -1;
                }
            }

            // WAITING FOR ALL THE SIGNING TO COMPLETE
            for (i = 0; i < NUM_THREADS; i++) {
                if (pthread_join(threads[i], NULL) != 0) {
                    printf("Error joining thread\n");
                    return -1;
                }

            }

            // VERIFYING IN A MULTITHREADED WAY
            for (i = 0; i < NUM_THREADS; i++) {
                // Create the threads and run the xmssmt_sign_open function (multithreaded)
                if (pthread_create(&threads[i], NULL, multi_xmss_sign_open, (void*)&vfpar) != 0) {
                    printf("Error creating thread\n");
                    return -1;
                }
            }
           
            // WAITING FOR ALL THE VERIFICATIONS TO COMPLETE
            for (i = 0; i < NUM_THREADS; i++) {
                if (pthread_join(threads[i], NULL) != 0) {
                    printf("Error joining thread\n");
                    return -1;
                }
            }

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

        printf("\nsignature_lenght=%llu\n", smlen);
        printf("sm="); hexdump(sm, smlen);
        #ifdef DEBUGGING
            printf("\nnew_sk="); hexdump(sk->secret_key, sk->length_secret_key);
        #endif

        /* ===================== SIGNATURE LENGTH CHECK ======================= */
   

        if (smlen != params.sig_bytes) {
            printf("  X smlen incorrect [%llu != %u]!\n", smlen, params.sig_bytes);
            ret = -1;
        }
        else 
            printf("    smlen as expected [%llu].\n", smlen);
        

        /* ========================= VERIFICATION ============================= */


        if(xmssmt){
            unsigned long long message_length = XMSS_MLEN;
            ret = xmssmt_sign_open(m, &message_length, sm, smlen, pk);
        }
        else {
            unsigned long long message_length = XMSS_MLEN;
            ret = xmss_sign_open(m, &message_length, sm, smlen, pk);
        }
        if (ret) {
            printf("  X verification failed!\n");
        }
        else {
            printf("    verification succeeded.\n");
        }

        if(ret) return ret;
    }

    OQS_SECRET_KEY_free(sk);
    free(m);
    free(sm);
    free(mout);
    return 0;
}

int main() {
    int rc = test_case(XMSS_IMPLEMENTATION, 0);
    if(rc != 0) return rc;
    return 0;
}