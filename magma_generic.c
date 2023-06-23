/*
 * GOST R 34.12-2015 (Magma) cipher.
 *
 * Copyright (c) 2018 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#include <linux/crypto.h>
#include <linux/module.h>
#include <asm/unaligned.h>
#include <crypto/algapi.h>
#include <crypto/magma.h>
#include <crypto/gost28147.h>

struct crypto_magma_ctx {
	u32 key[MAGMA_KEY_SIZE/4];
};

static int magma_set_key(struct crypto_tfm *tfm, const u8 *in_key,
		unsigned int key_len)
{
	struct crypto_magma_ctx *ctx = crypto_tfm_ctx(tfm);
	int i;

	if (key_len != MAGMA_KEY_SIZE)
		return -EINVAL;

	for (i = 0; i < MAGMA_KEY_SIZE / 4; i++, in_key += 4)
		ctx->key[i] = get_unaligned_be32(in_key);

	return 0;
}

static void magma_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct crypto_magma_ctx *ctx = crypto_tfm_ctx(tfm);
	const u32 *kp = ctx->key;
	u32 block[2];

	block[0] = get_unaligned_be32(in + 4);
	block[1] = get_unaligned_be32(in);
	crypto_gost28147_encrypt(kp, gost28147_param_TC26_Z.sbox, block, block);
	put_unaligned_be32(block[0], out + 4);
	put_unaligned_be32(block[1], out);
}

static void magma_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct crypto_magma_ctx *ctx = crypto_tfm_ctx(tfm);
	const u32 *kp = ctx->key;
	u32 block[2];

	block[0] = get_unaligned_be32(in + 4);
	block[1] = get_unaligned_be32(in);
	crypto_gost28147_decrypt(kp, gost28147_param_TC26_Z.sbox, block, block);
	put_unaligned_be32(block[0], out + 4);
	put_unaligned_be32(block[1], out);
}

static struct crypto_alg magma_alg = {
	.cra_name		=	"magma",
	.cra_driver_name	=	"magma-generic",
	.cra_priority		=	100,
	.cra_flags		=	CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		=	MAGMA_BLOCK_SIZE,
	.cra_ctxsize		=	sizeof(struct crypto_magma_ctx),
	.cra_module		=	THIS_MODULE,
	.cra_u			=	{
		.cipher = {
			.cia_min_keysize	= MAGMA_KEY_SIZE,
			.cia_max_keysize	= MAGMA_KEY_SIZE,
			.cia_setkey		= magma_set_key,
			.cia_encrypt		= magma_encrypt,
			.cia_decrypt		= magma_decrypt
		}
	}
};

static int __init magma_init(void)
{
	return crypto_register_alg(&magma_alg);
}

static void __exit magma_fini(void)
{
	crypto_unregister_alg(&magma_alg);
}

module_init(magma_init);
module_exit(magma_fini);

MODULE_DESCRIPTION("GOST R 34.12-2015 (Magma) algorithm");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_CRYPTO("magma");
MODULE_ALIAS_CRYPTO("magma-generic");
