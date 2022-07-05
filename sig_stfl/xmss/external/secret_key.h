#ifndef __SECRET_KEY_H__
#define __SECRET_KEY_H__

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct OQS_SECRET_KEY OQS_SECRET_KEY;

typedef struct OQS_SECRET_KEY {
	
	/** The (maximum) length, in bytes, of secret keys for this signature scheme. */
	unsigned long long length_secret_key;

	uint32_t oid;

	/** The physical secret key stored in memory as an array of bytes*/
	volatile uint8_t *secret_key;

	unsigned long long (*sigs_total)();

	unsigned long long (*sigs_left)();

	int (*lock_key)(OQS_SECRET_KEY *sk);
	int (*oqs_save_updated_sk_key)(OQS_SECRET_KEY *sk);
	int (*release_key)(OQS_SECRET_KEY *sk);

} OQS_SECRET_KEY;

// extern int (*oqs_save_updated_key)(OQS_SECRET_KEY *sk);

OQS_SECRET_KEY *OQS_SECRET_KEY_new(const char *method_name);

void OQS_SECRET_KEY_free(OQS_SECRET_KEY *sk);

#endif /* __SECRET_KEY_H__ */