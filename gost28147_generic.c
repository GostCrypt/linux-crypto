/* gost28147.c - GOST 28147-89 (Magma) cipher implementation
 *
 * based on Russian standard GOST 28147-89
 * For English description, check RFC 5830.
 * S-Boxes are expanded from the tables defined in RFC4357:
 *   https://tools.ietf.org/html/rfc4357
 *
 * Copyright: 2015-2015 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Copyright: 2009-2012 Aleksey Kravchenko <rhash.admin@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <crypto/gost28147.h>
#include <crypto/hash.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/crypto.h>
#include <linux/version.h>
#include <asm/byteorder.h>
#include <asm/unaligned.h>
#include "gost28147_param.h"

struct crypto_gost28147_ctx {
	const u32 *sbox;
	u32 key[GOST28147_KEY_SIZE/4];
};

struct crypto_gost28147_cfb_ctx {
	struct crypto_gost28147_ctx ctx;
	int key_meshing;
	unsigned int block_count;
};

struct crypto_gost28147imit_desc_ctx {
	const u32 *sbox;
	int key_meshing;
	unsigned int block_count;
	u32 key[GOST28147IMIT_KEY_SIZE/4];
	u32 state[GOST28147IMIT_BLOCK_SIZE/4];
	u32 count;
	u8 buffer[GOST28147IMIT_BLOCK_SIZE];
};

struct crypto_gost28147imit_ctx {
	u32 key[GOST28147IMIT_KEY_SIZE/4];
};

/* For gosthash94 module */
EXPORT_SYMBOL_GPL(gost28147_param_CryptoPro_3411);

/* For magma module */
EXPORT_SYMBOL_GPL(gost28147_param_TC26_Z);

/*
 *  A macro that performs a full encryption round of GOST 28147-89.
 *  Temporary variables tmp assumed and variables r and l for left and right
 *  blocks.
 *
 *  Do not enclose in do-while or braces, it will confuse optimizer.
 */
#define GOST_ENCRYPT_ROUND(key1, key2, sbox) \
	tmp = (key1) + r; \
	l ^= (sbox)[0*256 + (tmp & 0xff)] ^ \
	     (sbox)[1*256 + ((tmp >> 8) & 0xff)] ^ \
	     (sbox)[2*256 + ((tmp >> 16) & 0xff)] ^ \
	     (sbox)[3*256 + (tmp >> 24)]; \
	tmp = (key2) + l; \
	r ^= (sbox)[0*256 + (tmp & 0xff)] ^ \
	     (sbox)[1*256 + ((tmp >> 8) & 0xff)] ^ \
	     (sbox)[2*256 + ((tmp >> 16) & 0xff)] ^ \
	     (sbox)[3*256 + (tmp >> 24)]

/**
 * crypto_gost28147_set_key - Set the GOST28147 key.
 * @tfm:	The %crypto_tfm that is used in the context.
 * @in_key:	The input key.
 * @key_len:	The size of the key.
 * @param:	GOST parameters to be used.
 *
 * Returns 0 on success, on failure the %CRYPTO_TFM_RES_BAD_KEY_LEN flag in tfm
 * is set. &crypto_gost28147_ctx _must_ be the private data embedded in @tfm
 * which is retrieved with crypto_tfm_ctx().
 */
static int crypto_gost28147_set_key(struct crypto_tfm *tfm, const u8 *in_key,
		unsigned int key_len, const struct gost28147_param *param)
{
	struct crypto_gost28147_ctx *ctx = crypto_tfm_ctx(tfm);
	int i;

	if (key_len != GOST28147_KEY_SIZE) {
		crypto_tfm_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	};

	for (i = 0; i < GOST28147_KEY_SIZE / 4; i++, in_key += 4)
		ctx->key[i] = get_unaligned_le32(in_key);

	ctx->sbox = param->sbox;

	return 0;
}

static int gost28147_set_key_tc26z(struct crypto_tfm *tfm, const u8 *in_key,
		unsigned int key_len)
{
	return crypto_gost28147_set_key(tfm, in_key, key_len,
			&gost28147_param_TC26_Z);
}

static int gost28147_set_key_cpa(struct crypto_tfm *tfm, const u8 *in_key,
		unsigned int key_len)
{
	return crypto_gost28147_set_key(tfm, in_key, key_len,
			&gost28147_param_CryptoPro_A);
}

static int gost28147_set_key_cpb(struct crypto_tfm *tfm, const u8 *in_key,
		unsigned int key_len)
{
	return crypto_gost28147_set_key(tfm, in_key, key_len,
			&gost28147_param_CryptoPro_B);
}

static int gost28147_set_key_cpc(struct crypto_tfm *tfm, const u8 *in_key,
		unsigned int key_len)
{
	return crypto_gost28147_set_key(tfm, in_key, key_len,
			&gost28147_param_CryptoPro_C);
}

static int gost28147_set_key_cpd(struct crypto_tfm *tfm, const u8 *in_key,
		unsigned int key_len)
{
	return crypto_gost28147_set_key(tfm, in_key, key_len,
			&gost28147_param_CryptoPro_D);
}

/* Encrypt a single block */

void crypto_gost28147_encrypt(const u32 *kp, const u32 *sbox,
		const u32 *in, u32 *out)
{
	u32 l, r, tmp;

	r = in[0];
	l = in[1];
	GOST_ENCRYPT_ROUND(kp[0], kp[1], sbox);
	GOST_ENCRYPT_ROUND(kp[2], kp[3], sbox);
	GOST_ENCRYPT_ROUND(kp[4], kp[5], sbox);
	GOST_ENCRYPT_ROUND(kp[6], kp[7], sbox);
	GOST_ENCRYPT_ROUND(kp[0], kp[1], sbox);
	GOST_ENCRYPT_ROUND(kp[2], kp[3], sbox);
	GOST_ENCRYPT_ROUND(kp[4], kp[5], sbox);
	GOST_ENCRYPT_ROUND(kp[6], kp[7], sbox);
	GOST_ENCRYPT_ROUND(kp[0], kp[1], sbox);
	GOST_ENCRYPT_ROUND(kp[2], kp[3], sbox);
	GOST_ENCRYPT_ROUND(kp[4], kp[5], sbox);
	GOST_ENCRYPT_ROUND(kp[6], kp[7], sbox);
	GOST_ENCRYPT_ROUND(kp[7], kp[6], sbox);
	GOST_ENCRYPT_ROUND(kp[5], kp[4], sbox);
	GOST_ENCRYPT_ROUND(kp[3], kp[2], sbox);
	GOST_ENCRYPT_ROUND(kp[1], kp[0], sbox);
	out[0] = l;
	out[1] = r;
}
EXPORT_SYMBOL_GPL(crypto_gost28147_encrypt);

static void gost28147_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct crypto_gost28147_ctx *ctx = crypto_tfm_ctx(tfm);
	const u32 *kp = ctx->key;
	const u32 *sbox = ctx->sbox;
	u32 block[2];

	block[0] = get_unaligned_le32(in);
	block[1] = get_unaligned_le32(in + 4);
	crypto_gost28147_encrypt(kp, sbox, block, block);
	put_unaligned_le32(block[0], out);
	put_unaligned_le32(block[1], out + 4);
}

/* decrypt a block of text */
void crypto_gost28147_decrypt(const u32 *kp, const u32 *sbox,
		const u32 *in, u32 *out)
{
	u32 l, r, tmp;

	r = in[0];
	l = in[1];
	GOST_ENCRYPT_ROUND(kp[0], kp[1], sbox);
	GOST_ENCRYPT_ROUND(kp[2], kp[3], sbox);
	GOST_ENCRYPT_ROUND(kp[4], kp[5], sbox);
	GOST_ENCRYPT_ROUND(kp[6], kp[7], sbox);
	GOST_ENCRYPT_ROUND(kp[7], kp[6], sbox);
	GOST_ENCRYPT_ROUND(kp[5], kp[4], sbox);
	GOST_ENCRYPT_ROUND(kp[3], kp[2], sbox);
	GOST_ENCRYPT_ROUND(kp[1], kp[0], sbox);
	GOST_ENCRYPT_ROUND(kp[7], kp[6], sbox);
	GOST_ENCRYPT_ROUND(kp[5], kp[4], sbox);
	GOST_ENCRYPT_ROUND(kp[3], kp[2], sbox);
	GOST_ENCRYPT_ROUND(kp[1], kp[0], sbox);
	GOST_ENCRYPT_ROUND(kp[7], kp[6], sbox);
	GOST_ENCRYPT_ROUND(kp[5], kp[4], sbox);
	GOST_ENCRYPT_ROUND(kp[3], kp[2], sbox);
	GOST_ENCRYPT_ROUND(kp[1], kp[0], sbox);
	out[0] = l;
	out[1] = r;
}
EXPORT_SYMBOL_GPL(crypto_gost28147_decrypt);

static void gost28147_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct crypto_gost28147_ctx *ctx = crypto_tfm_ctx(tfm);
	const u32 *kp = ctx->key;
	const u32 *sbox = ctx->sbox;
	u32 block[2];

	block[0] = get_unaligned_le32(in);
	block[1] = get_unaligned_le32(in + 4);
	crypto_gost28147_decrypt(kp, sbox, block, block);
	put_unaligned_le32(block[0], out);
	put_unaligned_le32(block[1], out + 4);
}

static const u32 gost28147_key_mesh_cryptopro_data[GOST28147_KEY_SIZE / 4] = {
	0x22720069, 0x2304c964,
	0x96db3a8d, 0xc42ae946,
	0x94acfe18, 0x1207ed00,
	0xc2dc86c0, 0x2ba94cef,
};

static void gost28147_key_mesh_cryptopro(u32 *key, const u32 *sbox)
{
	uint32_t newkey[GOST28147_KEY_SIZE/4];

	crypto_gost28147_decrypt(key, sbox,
			&gost28147_key_mesh_cryptopro_data[0],
			&newkey[0]);

	crypto_gost28147_decrypt(key, sbox,
			&gost28147_key_mesh_cryptopro_data[2],
			&newkey[2]);

	crypto_gost28147_decrypt(key, sbox,
			&gost28147_key_mesh_cryptopro_data[4],
			&newkey[4]);

	crypto_gost28147_decrypt(key, sbox,
			&gost28147_key_mesh_cryptopro_data[6],
			&newkey[6]);

	memcpy(key, newkey, sizeof(newkey));
}

static int gost28147_cfb_setkey(struct crypto_skcipher *tfm, const u8 *key,
		unsigned int len, const struct gost28147_param *param)
{
	struct crypto_gost28147_cfb_ctx *ctx = crypto_skcipher_ctx(tfm);

	ctx->block_count = 0;
	ctx->key_meshing = param->key_meshing;
	return crypto_gost28147_set_key(crypto_skcipher_tfm(tfm),
			key, len, param);
}

static int gost28147_cfb_setkey_tc26z(struct crypto_skcipher *tfm, const u8 *key,
		unsigned int len)
{
	return gost28147_cfb_setkey(tfm, key, len, &gost28147_param_TC26_Z);
}

static int gost28147_cfb_setkey_cpa(struct crypto_skcipher *tfm, const u8 *key,
		unsigned int len)
{
	return gost28147_cfb_setkey(tfm, key, len, &gost28147_param_CryptoPro_A);
}

static int gost28147_cfb_setkey_cpb(struct crypto_skcipher *tfm, const u8 *key,
		unsigned int len)
{
	return gost28147_cfb_setkey(tfm, key, len, &gost28147_param_CryptoPro_B);
}

static int gost28147_cfb_setkey_cpc(struct crypto_skcipher *tfm, const u8 *key,
		unsigned int len)
{
	return gost28147_cfb_setkey(tfm, key, len, &gost28147_param_CryptoPro_C);
}

static int gost28147_cfb_setkey_cpd(struct crypto_skcipher *tfm, const u8 *key,
		unsigned int len)
{
	return gost28147_cfb_setkey(tfm, key, len, &gost28147_param_CryptoPro_D);
}

static void gost28147_cfb_encrypt_one(struct crypto_skcipher *tfm,
		u8 *src, u8 *dst)
{
	struct crypto_gost28147_cfb_ctx *ctx = crypto_skcipher_ctx(tfm);
	u32 *kp = ctx->ctx.key;
	const u32 *sbox = ctx->ctx.sbox;
	u32 block[2];

	block[0] = get_unaligned_le32(src);
	block[1] = get_unaligned_le32(src + 4);
	if (ctx->key_meshing && ctx->block_count == 1024 / GOST28147_BLOCK_SIZE) {
		gost28147_key_mesh_cryptopro(kp, sbox);
		crypto_gost28147_encrypt(kp, sbox, block, block);
		ctx->block_count = 0;
	}

	crypto_gost28147_encrypt(kp, sbox, block, block);
	put_unaligned_le32(block[0], dst);
	put_unaligned_le32(block[1], dst + 4);
	ctx->block_count++;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static inline void crypto_xor_cpy(u8 *dst, const u8 *src1, const u8 *src2,
				  unsigned int size)
{
	memcpy(dst, src1, size);
	crypto_xor(dst, src2, size);
}
#endif

/* final encrypt and decrypt is the same */
static void gost28147_cfb_final(struct skcipher_walk *walk,
			     struct crypto_skcipher *tfm)
{
	u8 tmp[GOST28147_BLOCK_SIZE];
	u8 *src = walk->src.virt.addr;
	u8 *dst = walk->dst.virt.addr;
	u8 *iv = walk->iv;
	unsigned int nbytes = walk->nbytes;

	gost28147_cfb_encrypt_one(tfm, iv, tmp);
	crypto_xor_cpy(dst, tmp, src, nbytes);
}

static int gost28147_cfb_encrypt_segment(struct skcipher_walk *walk,
				      struct crypto_skcipher *tfm)
{
	const unsigned int bsize = GOST28147_BLOCK_SIZE;
	unsigned int nbytes = walk->nbytes;
	u8 *src = walk->src.virt.addr;
	u8 *dst = walk->dst.virt.addr;
	u8 *iv = walk->iv;

	do {
		gost28147_cfb_encrypt_one(tfm, iv, dst);
		crypto_xor(dst, src, bsize);
		memcpy(iv, dst, bsize);

		src += bsize;
		dst += bsize;
	} while ((nbytes -= bsize) >= bsize);

	return nbytes;
}

static int gost28147_cfb_encrypt_inplace(struct skcipher_walk *walk,
				      struct crypto_skcipher *tfm)
{
	const unsigned int bsize = GOST28147_BLOCK_SIZE;
	unsigned int nbytes = walk->nbytes;
	u8 *src = walk->src.virt.addr;
	u8 *iv = walk->iv;
	u8 tmp[GOST28147_BLOCK_SIZE];

	do {
		gost28147_cfb_encrypt_one(tfm, iv, tmp);
		crypto_xor(src, tmp, bsize);
		iv = src;

		src += bsize;
	} while ((nbytes -= bsize) >= bsize);

	memcpy(walk->iv, iv, bsize);

	return nbytes;
}

static int gost28147_cfb_encrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct skcipher_walk walk;
	unsigned int bsize = GOST28147_BLOCK_SIZE;
	int err;

	err = skcipher_walk_virt(&walk, req, false);

	while (walk.nbytes >= bsize) {
		if (walk.src.virt.addr == walk.dst.virt.addr)
			err = gost28147_cfb_encrypt_inplace(&walk, tfm);
		else
			err = gost28147_cfb_encrypt_segment(&walk, tfm);
		err = skcipher_walk_done(&walk, err);
	}

	if (walk.nbytes) {
		gost28147_cfb_final(&walk, tfm);
		err = skcipher_walk_done(&walk, 0);
	}

	return err;
}

static int gost28147_cfb_decrypt_segment(struct skcipher_walk *walk,
				      struct crypto_skcipher *tfm)
{
	const unsigned int bsize = GOST28147_BLOCK_SIZE;
	unsigned int nbytes = walk->nbytes;
	u8 *src = walk->src.virt.addr;
	u8 *dst = walk->dst.virt.addr;
	u8 *iv = walk->iv;

	do {
		gost28147_cfb_encrypt_one(tfm, iv, dst);
		crypto_xor(dst, src, bsize);
		iv = src;

		src += bsize;
		dst += bsize;
	} while ((nbytes -= bsize) >= bsize);

	memcpy(walk->iv, iv, bsize);

	return nbytes;
}

static int gost28147_cfb_decrypt_inplace(struct skcipher_walk *walk,
				      struct crypto_skcipher *tfm)
{
	const unsigned int bsize = GOST28147_BLOCK_SIZE;
	unsigned int nbytes = walk->nbytes;
	u8 *src = walk->src.virt.addr;
	u8 *iv = walk->iv;
	u8 tmp[GOST28147_BLOCK_SIZE];

	do {
		gost28147_cfb_encrypt_one(tfm, iv, tmp);
		memcpy(iv, src, bsize);
		crypto_xor(src, tmp, bsize);
		src += bsize;
	} while ((nbytes -= bsize) >= bsize);

	memcpy(walk->iv, iv, bsize);

	return nbytes;
}

static int gost28147_cfb_decrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct skcipher_walk walk;
	const unsigned int bsize = GOST28147_BLOCK_SIZE;
	int err;

	err = skcipher_walk_virt(&walk, req, false);

	while (walk.nbytes >= bsize) {
		if (walk.src.virt.addr == walk.dst.virt.addr)
			err = gost28147_cfb_decrypt_inplace(&walk, tfm);
		else
			err = gost28147_cfb_decrypt_segment(&walk, tfm);
		err = skcipher_walk_done(&walk, err);
	}

	if (walk.nbytes) {
		gost28147_cfb_final(&walk, tfm);
		err = skcipher_walk_done(&walk, 0);
	}

	return err;
}

static int gost28147imit_init(struct shash_desc *desc, const struct gost28147_param *param)
{
	struct crypto_gost28147imit_desc_ctx *ctx = shash_desc_ctx(desc);
	struct crypto_gost28147imit_ctx *tfm_ctx = crypto_shash_ctx(desc->tfm);

	ctx->state[0] = 0;
	ctx->state[1] = 0;
	ctx->count = 0;
	ctx->sbox = param->sbox;
	ctx->key_meshing = param->key_meshing;
	ctx->block_count = 0;
	memcpy(ctx->key, tfm_ctx->key, sizeof(ctx->key));

	return 0;
}

static int gost28147imit_tc26z_init(struct shash_desc *desc)
{
	return gost28147imit_init(desc, &gost28147_param_TC26_Z);
}

static int gost28147imit_cpa_init(struct shash_desc *desc)
{
	return gost28147imit_init(desc, &gost28147_param_CryptoPro_A);
}

static int gost28147imit_cpb_init(struct shash_desc *desc)
{
	return gost28147imit_init(desc, &gost28147_param_CryptoPro_B);
}

static int gost28147imit_cpc_init(struct shash_desc *desc)
{
	return gost28147imit_init(desc, &gost28147_param_CryptoPro_C);
}

static int gost28147imit_cpd_init(struct shash_desc *desc)
{
	return gost28147imit_init(desc, &gost28147_param_CryptoPro_D);
}

static int gost28147imit_setkey(struct crypto_shash *tfm, const u8 *key,
		unsigned int key_len)
{
	struct crypto_gost28147imit_ctx *ctx = crypto_shash_ctx(tfm);
	int i;

	if (key_len != GOST28147IMIT_KEY_SIZE) {
		crypto_shash_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	};

	for (i = 0; i < GOST28147IMIT_KEY_SIZE / 4; i++, key += 4)
		ctx->key[i] = get_unaligned_le32(key);

	return 0;
}

static inline void gost28147_imit_simple(const u32 *key, const u32 *sbox,
		const u32 *in, u32 *out)
{
	u32 l, r, tmp;

	r = in[0];
	l = in[1];
	GOST_ENCRYPT_ROUND(key[0], key[1], sbox);
	GOST_ENCRYPT_ROUND(key[2], key[3], sbox);
	GOST_ENCRYPT_ROUND(key[4], key[5], sbox);
	GOST_ENCRYPT_ROUND(key[6], key[7], sbox);
	GOST_ENCRYPT_ROUND(key[0], key[1], sbox);
	GOST_ENCRYPT_ROUND(key[2], key[3], sbox);
	GOST_ENCRYPT_ROUND(key[4], key[5], sbox);
	GOST_ENCRYPT_ROUND(key[6], key[7], sbox);
	*out = r;
	*(out + 1) = l;
}

static void gost28147_imit_compress(struct crypto_gost28147imit_desc_ctx *ctx,
		const u8 *data, unsigned int blocks)
{
	u32 block[2];
	unsigned int i;

	for (i = 0; i < blocks; i++, data += GOST28147IMIT_BLOCK_SIZE) {
		if (ctx->key_meshing && ctx->block_count == 1024 / GOST28147IMIT_BLOCK_SIZE) {
			gost28147_key_mesh_cryptopro(ctx->key, ctx->sbox);
			ctx->block_count = 0;
		}

		block[0] = get_unaligned_le32(data + 0) ^ ctx->state[0];
		block[1] = get_unaligned_le32(data + 4) ^ ctx->state[1];
		gost28147_imit_simple(ctx->key, ctx->sbox, block, ctx->state);
		ctx->block_count++;
	}
}

static int gost28147imit_update(struct shash_desc *desc, const u8 *data, unsigned int len)
{
	struct crypto_gost28147imit_desc_ctx *sctx = shash_desc_ctx(desc);
	unsigned int partial = sctx->count % GOST28147IMIT_BLOCK_SIZE;

	sctx->count += len;

	if (unlikely((partial + len) >= GOST28147IMIT_BLOCK_SIZE)) {
		int blocks;

		if (partial) {
			int p = GOST28147IMIT_BLOCK_SIZE - partial;

			memcpy(sctx->buffer + partial, data, p);
			data += p;
			len -= p;

			gost28147_imit_compress(sctx, sctx->buffer, 1);
		}

		blocks = len / GOST28147IMIT_BLOCK_SIZE;
		len %= GOST28147IMIT_BLOCK_SIZE;

		if (blocks) {
			gost28147_imit_compress(sctx, data, blocks);
			data += blocks * GOST28147IMIT_BLOCK_SIZE;
		}
		partial = 0;
	}
	if (len)
		memcpy(sctx->buffer + partial, data, len);

	return 0;
}

const u8 zero_block_block[GOST28147IMIT_BLOCK_SIZE] = { 0 };

static int gost28147imit_final(struct shash_desc *desc, u8 *out)
{
	struct crypto_gost28147imit_desc_ctx *sctx = shash_desc_ctx(desc);
	unsigned int partial = sctx->count % GOST28147IMIT_BLOCK_SIZE;

	if (partial) {
		memset(sctx->buffer + partial, 0, GOST28147IMIT_BLOCK_SIZE - partial);
		sctx->count += GOST28147IMIT_BLOCK_SIZE - partial;
		gost28147_imit_compress(sctx, sctx->buffer, 1);
	}

	if (sctx->count == GOST28147IMIT_BLOCK_SIZE)
		gost28147_imit_compress(sctx, zero_block_block, 1);

	put_unaligned_le32(sctx->state[0], out);

	return 0;
}

static struct crypto_alg gost28147_algs[] = { {
	.cra_name		=	"gost28147-tc26z",
	.cra_driver_name	=	"gost28147-tc26z-generic",
	.cra_priority		=	100,
	.cra_flags		=	CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		=	GOST28147_BLOCK_SIZE,
	.cra_ctxsize		=	sizeof(struct crypto_gost28147_ctx),
	.cra_module		=	THIS_MODULE,
	.cra_u			=	{
		.cipher = {
			.cia_min_keysize	= GOST28147_KEY_SIZE,
			.cia_max_keysize	= GOST28147_KEY_SIZE,
			.cia_setkey		= gost28147_set_key_tc26z,
			.cia_encrypt		= gost28147_encrypt,
			.cia_decrypt		= gost28147_decrypt
		}
	}
}, {
	.cra_name		=	"gost28147-cpa",
	.cra_driver_name	=	"gost28147-cpa-generic",
	.cra_priority		=	100,
	.cra_flags		=	CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		=	GOST28147_BLOCK_SIZE,
	.cra_ctxsize		=	sizeof(struct crypto_gost28147_ctx),
	.cra_module		=	THIS_MODULE,
	.cra_u			=	{
		.cipher = {
			.cia_min_keysize	= GOST28147_KEY_SIZE,
			.cia_max_keysize	= GOST28147_KEY_SIZE,
			.cia_setkey		= gost28147_set_key_cpa,
			.cia_encrypt		= gost28147_encrypt,
			.cia_decrypt		= gost28147_decrypt
		}
	}
}, {
	.cra_name		=	"gost28147-cpb",
	.cra_driver_name	=	"gost28147-cpb-generic",
	.cra_priority		=	100,
	.cra_flags		=	CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		=	GOST28147_BLOCK_SIZE,
	.cra_ctxsize		=	sizeof(struct crypto_gost28147_ctx),
	.cra_module		=	THIS_MODULE,
	.cra_u			=	{
		.cipher = {
			.cia_min_keysize	= GOST28147_KEY_SIZE,
			.cia_max_keysize	= GOST28147_KEY_SIZE,
			.cia_setkey		= gost28147_set_key_cpb,
			.cia_encrypt		= gost28147_encrypt,
			.cia_decrypt		= gost28147_decrypt
		}
	}
}, {
	.cra_name		=	"gost28147-cpc",
	.cra_driver_name	=	"gost28147-cpc-generic",
	.cra_priority		=	100,
	.cra_flags		=	CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		=	GOST28147_BLOCK_SIZE,
	.cra_ctxsize		=	sizeof(struct crypto_gost28147_ctx),
	.cra_module		=	THIS_MODULE,
	.cra_u			=	{
		.cipher = {
			.cia_min_keysize	= GOST28147_KEY_SIZE,
			.cia_max_keysize	= GOST28147_KEY_SIZE,
			.cia_setkey		= gost28147_set_key_cpc,
			.cia_encrypt		= gost28147_encrypt,
			.cia_decrypt		= gost28147_decrypt
		}
	}
}, {
	.cra_name		=	"gost28147-cpd",
	.cra_driver_name	=	"gost28147-cpd-generic",
	.cra_priority		=	100,
	.cra_flags		=	CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		=	GOST28147_BLOCK_SIZE,
	.cra_ctxsize		=	sizeof(struct crypto_gost28147_ctx),
	.cra_module		=	THIS_MODULE,
	.cra_u			=	{
		.cipher = {
			.cia_min_keysize	= GOST28147_KEY_SIZE,
			.cia_max_keysize	= GOST28147_KEY_SIZE,
			.cia_setkey		= gost28147_set_key_cpd,
			.cia_encrypt		= gost28147_encrypt,
			.cia_decrypt		= gost28147_decrypt
		}
	}
} };

static struct skcipher_alg gost28147_mode_algs[] = { {
	.min_keysize	= GOST28147_KEY_SIZE,
	.max_keysize	= GOST28147_KEY_SIZE,
	.ivsize		= GOST28147_IV_SIZE,
	.chunksize	= GOST28147_BLOCK_SIZE,
	.setkey		= gost28147_cfb_setkey_tc26z,
	.encrypt	= gost28147_cfb_encrypt,
	.decrypt	= gost28147_cfb_decrypt,
	.base		= {
		.cra_name	=	"cfb(gost28147-tc26z)",
		.cra_driver_name =	"cfb-gost28147-tc26z-generic",
		.cra_priority	=	100,
		.cra_blocksize	=	1,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147_cfb_ctx),
		.cra_module	=	THIS_MODULE,
	}
}, {
	.min_keysize	= GOST28147_KEY_SIZE,
	.max_keysize	= GOST28147_KEY_SIZE,
	.ivsize		= GOST28147_IV_SIZE,
	.chunksize	= GOST28147_BLOCK_SIZE,
	.setkey		= gost28147_cfb_setkey_cpa,
	.encrypt	= gost28147_cfb_encrypt,
	.decrypt	= gost28147_cfb_decrypt,
	.base		= {
		.cra_name	=	"cfb(gost28147-cpa)",
		.cra_driver_name =	"cfb-gost28147-cpa-generic",
		.cra_priority	=	100,
		.cra_blocksize	=	1,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147_cfb_ctx),
		.cra_module	=	THIS_MODULE,
	}
}, {
	.min_keysize	= GOST28147_KEY_SIZE,
	.max_keysize	= GOST28147_KEY_SIZE,
	.ivsize		= GOST28147_IV_SIZE,
	.chunksize	= GOST28147_BLOCK_SIZE,
	.setkey		= gost28147_cfb_setkey_cpb,
	.encrypt	= gost28147_cfb_encrypt,
	.decrypt	= gost28147_cfb_decrypt,
	.base		= {
		.cra_name	=	"cfb(gost28147-cpb)",
		.cra_driver_name =	"cfb-gost28147-cpb-generic",
		.cra_priority	=	100,
		.cra_blocksize	=	1,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147_cfb_ctx),
		.cra_module	=	THIS_MODULE,
	}
}, {
	.min_keysize	= GOST28147_KEY_SIZE,
	.max_keysize	= GOST28147_KEY_SIZE,
	.ivsize		= GOST28147_IV_SIZE,
	.chunksize	= GOST28147_BLOCK_SIZE,
	.setkey		= gost28147_cfb_setkey_cpc,
	.encrypt	= gost28147_cfb_encrypt,
	.decrypt	= gost28147_cfb_decrypt,
	.base		= {
		.cra_name	=	"cfb(gost28147-cpc)",
		.cra_driver_name =	"cfb-gost28147-cpc-generic",
		.cra_priority	=	100,
		.cra_blocksize	=	1,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147_cfb_ctx),
		.cra_module	=	THIS_MODULE,
	}
}, {
	.min_keysize	= GOST28147_KEY_SIZE,
	.max_keysize	= GOST28147_KEY_SIZE,
	.ivsize		= GOST28147_IV_SIZE,
	.chunksize	= GOST28147_BLOCK_SIZE,
	.setkey		= gost28147_cfb_setkey_cpd,
	.encrypt	= gost28147_cfb_encrypt,
	.decrypt	= gost28147_cfb_decrypt,
	.base		= {
		.cra_name	=	"cfb(gost28147-cpd)",
		.cra_driver_name =	"cfb-gost28147-cpd-generic",
		.cra_priority	=	100,
		.cra_blocksize	=	1,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147_cfb_ctx),
		.cra_module	=	THIS_MODULE,
	}
} };

static struct shash_alg gost28147imit_algs[] = { {
	.digestsize	= GOST28147IMIT_DIGEST_SIZE,
	.init		= gost28147imit_tc26z_init,
	.setkey		= gost28147imit_setkey,
	.update		= gost28147imit_update,
	.final		= gost28147imit_final,
	.descsize	= sizeof(struct crypto_gost28147imit_desc_ctx),
	.base		= {
		.cra_name	=	"gost28147imit-tc26z",
		.cra_driver_name =	"gost28147imit-tc26z-generic",
		.cra_priority	=	100,
		.cra_flags	=	CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize	=	GOST28147IMIT_BLOCK_SIZE,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147imit_ctx),
		.cra_module	=	THIS_MODULE,
	}
}, {
	.digestsize	= GOST28147IMIT_DIGEST_SIZE,
	.init		= gost28147imit_cpa_init,
	.setkey		= gost28147imit_setkey,
	.update		= gost28147imit_update,
	.final		= gost28147imit_final,
	.descsize	= sizeof(struct crypto_gost28147imit_desc_ctx),
	.base		= {
		.cra_name	=	"gost28147imit-cpa",
		.cra_driver_name =	"gost28147imit-cpa-generic",
		.cra_priority	=	100,
		.cra_flags	=	CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize	=	GOST28147IMIT_BLOCK_SIZE,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147imit_ctx),
		.cra_module	=	THIS_MODULE,
	}
}, {
	.digestsize	= GOST28147IMIT_DIGEST_SIZE,
	.init		= gost28147imit_cpb_init,
	.setkey		= gost28147imit_setkey,
	.update		= gost28147imit_update,
	.final		= gost28147imit_final,
	.descsize	= sizeof(struct crypto_gost28147imit_desc_ctx),
	.base		= {
		.cra_name	=	"gost28147imit-cpb",
		.cra_driver_name =	"gost28147imit-cpb-generic",
		.cra_priority	=	100,
		.cra_flags	=	CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize	=	GOST28147IMIT_BLOCK_SIZE,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147imit_ctx),
		.cra_module	=	THIS_MODULE,
	}
}, {
	.digestsize	= GOST28147IMIT_DIGEST_SIZE,
	.init		= gost28147imit_cpc_init,
	.setkey		= gost28147imit_setkey,
	.update		= gost28147imit_update,
	.final		= gost28147imit_final,
	.descsize	= sizeof(struct crypto_gost28147imit_desc_ctx),
	.base		= {
		.cra_name	=	"gost28147imit-cpc",
		.cra_driver_name =	"gost28147imit-cpc-generic",
		.cra_priority	=	100,
		.cra_flags	=	CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize	=	GOST28147IMIT_BLOCK_SIZE,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147imit_ctx),
		.cra_module	=	THIS_MODULE,
	}
}, {
	.digestsize	= GOST28147IMIT_DIGEST_SIZE,
	.init		= gost28147imit_cpd_init,
	.setkey		= gost28147imit_setkey,
	.update		= gost28147imit_update,
	.final		= gost28147imit_final,
	.descsize	= sizeof(struct crypto_gost28147imit_desc_ctx),
	.base		= {
		.cra_name	=	"gost28147imit-cpd",
		.cra_driver_name =	"gost28147imit-cpd-generic",
		.cra_priority	=	100,
		.cra_flags	=	CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize	=	GOST28147IMIT_BLOCK_SIZE,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147imit_ctx),
		.cra_module	=	THIS_MODULE,
	}
} };

static int __init gost28147_init(void)
{
	int ret;

	ret = crypto_register_algs(gost28147_algs, ARRAY_SIZE(gost28147_algs));
	if (ret < 0)
		return ret;

	ret = crypto_register_skciphers(gost28147_mode_algs, ARRAY_SIZE(gost28147_mode_algs));
	if (ret < 0)
		goto err_skciphers;

	ret = crypto_register_shashes(gost28147imit_algs, ARRAY_SIZE(gost28147imit_algs));
	if (ret < 0)
		goto err_shashes;

	return 0;

err_shashes:
	crypto_unregister_skciphers(gost28147_mode_algs, ARRAY_SIZE(gost28147_mode_algs));
err_skciphers:
	crypto_unregister_algs(gost28147_algs, ARRAY_SIZE(gost28147_algs));

	return ret;
}

static void __exit gost28147_fini(void)
{
	crypto_unregister_shashes(gost28147imit_algs, ARRAY_SIZE(gost28147imit_algs));
	crypto_unregister_skciphers(gost28147_mode_algs, ARRAY_SIZE(gost28147_mode_algs));
	crypto_unregister_algs(gost28147_algs, ARRAY_SIZE(gost28147_algs));
}

module_init(gost28147_init);
module_exit(gost28147_fini);

MODULE_DESCRIPTION("GOST 28147-89 (Magma) algorithm");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_CRYPTO("gost28147-tc26z");
MODULE_ALIAS_CRYPTO("gost28147-tc26z-generic");
MODULE_ALIAS_CRYPTO("gost28147-cpa");
MODULE_ALIAS_CRYPTO("gost28147-cpa-generic");
MODULE_ALIAS_CRYPTO("gost28147-cpb");
MODULE_ALIAS_CRYPTO("gost28147-cpb-generic");
MODULE_ALIAS_CRYPTO("gost28147-cpc");
MODULE_ALIAS_CRYPTO("gost28147-cpc-generic");
MODULE_ALIAS_CRYPTO("gost28147-cpd");
MODULE_ALIAS_CRYPTO("gost28147-cpd-generic");
MODULE_ALIAS_CRYPTO("gost28147imit-tc26z");
MODULE_ALIAS_CRYPTO("gost28147imit-tc26z-generic");
MODULE_ALIAS_CRYPTO("gost28147imit-cpa");
MODULE_ALIAS_CRYPTO("gost28147imit-cpa-generic");
MODULE_ALIAS_CRYPTO("gost28147imit-cpb");
MODULE_ALIAS_CRYPTO("gost28147imit-cpb-generic");
MODULE_ALIAS_CRYPTO("gost28147imit-cpc");
MODULE_ALIAS_CRYPTO("gost28147imit-cpc-generic");
MODULE_ALIAS_CRYPTO("gost28147imit-cpd");
MODULE_ALIAS_CRYPTO("gost28147imit-cpd-generic");
