#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


#define XMSS_IMPLEMENTATION "XMSS-SHA2_16_256"
#define XMSS_MLEN 32
#define NUM_TESTS 15
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

    unsigned char filename[MAX_LENGTH_FILENAME] = "./keys/reg2_xmssmt60_3_sha256.prv";

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
    }
    fclose(printer);
    printf("Completed the write operation\n");
    return 0;
}

/** =========================================================================== */

int main() {
    
}