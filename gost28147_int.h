#ifndef _GOST28147_INT_H
#define _GOST28147_INT_H

int gost28147_modes_init(void);
void gost28147_modes_fini(void);

struct crypto_gost28147_ctx {
	const u32 *sbox;
	u32 key[GOST28147_KEY_SIZE/4];
};

int crypto_gost28147_set_key(struct crypto_tfm *tfm, const u8 *in_key,
		unsigned int key_len, const struct gost28147_param *param);

#endif
