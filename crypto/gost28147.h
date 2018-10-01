/*
 * Common values for GOST28147 algorithms
 */

#ifndef _CRYPTO_GOST28147_H
#define _CRYPTO_GOST28147_H

#include <linux/types.h>
#include <linux/crypto.h>

#define GOST28147_KEY_SIZE	32
#define GOST28147_BLOCK_SIZE	8

struct gost28147_param {
	int key_meshing;
	u32 sbox[4*256];
};

extern const struct gost28147_param gost28147_param_test_3411;
extern const struct gost28147_param gost28147_param_CryptoPro_3411;
extern const struct gost28147_param gost28147_param_Test_89;
extern const struct gost28147_param gost28147_param_CryptoPro_A;
extern const struct gost28147_param gost28147_param_CryptoPro_B;
extern const struct gost28147_param gost28147_param_CryptoPro_C;
extern const struct gost28147_param gost28147_param_CryptoPro_D;
extern const struct gost28147_param gost28147_param_TC26_Z;

void crypto_gost28147_encrypt(const u32 *key, const u32 *sbox,
		const u32 *in, u32 *out);
#endif
