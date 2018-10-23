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
#include <crypto/internal/skcipher.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/crypto.h>
#include <linux/version.h>
#include <asm/byteorder.h>
#include <asm/unaligned.h>
#include "gost28147_int.h"

struct crypto_gost28147_mode_ctx {
	struct crypto_gost28147_ctx ctx;
	int key_meshing;
	unsigned int block_count;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static inline void crypto_xor_cpy(u8 *dst, const u8 *src1, const u8 *src2,
				  unsigned int size)
{
	memcpy(dst, src1, size);
	crypto_xor(dst, src2, size);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
#define crypto_skcipher crypto_tfm
#define crypto_skcipher_ctx(tfm) crypto_tfm_ctx(tfm)
#define crypto_skcipher_tfm(tfm) (tfm)
#define skcipher_walk blkcipher_walk
#endif

static int gost28147_mode_setkey(struct crypto_skcipher *tfm, const u8 *key,
		unsigned int len, const struct gost28147_param *param)
{
	struct crypto_gost28147_mode_ctx *ctx = crypto_skcipher_ctx(tfm);

	ctx->block_count = 0;
	ctx->key_meshing = param->key_meshing;
	return crypto_gost28147_set_key(crypto_skcipher_tfm(tfm),
			key, len, param);
}

static int gost28147_mode_setkey_tc26z(struct crypto_skcipher *tfm, const u8 *key,
		unsigned int len)
{
	return gost28147_mode_setkey(tfm, key, len, &gost28147_param_TC26_Z);
}

static int gost28147_mode_setkey_cpa(struct crypto_skcipher *tfm, const u8 *key,
		unsigned int len)
{
	return gost28147_mode_setkey(tfm, key, len, &gost28147_param_CryptoPro_A);
}

static int gost28147_mode_setkey_cpb(struct crypto_skcipher *tfm, const u8 *key,
		unsigned int len)
{
	return gost28147_mode_setkey(tfm, key, len, &gost28147_param_CryptoPro_B);
}

static int gost28147_mode_setkey_cpc(struct crypto_skcipher *tfm, const u8 *key,
		unsigned int len)
{
	return gost28147_mode_setkey(tfm, key, len, &gost28147_param_CryptoPro_C);
}

static int gost28147_mode_setkey_cpd(struct crypto_skcipher *tfm, const u8 *key,
		unsigned int len)
{
	return gost28147_mode_setkey(tfm, key, len, &gost28147_param_CryptoPro_D);
}

static void gost28147_cfb_encrypt_one(struct crypto_skcipher *tfm,
		u8 *src, u8 *dst)
{
	struct crypto_gost28147_mode_ctx *ctx = crypto_skcipher_ctx(tfm);
	u32 *kp = ctx->ctx.key;
	const u32 *sbox = ctx->ctx.sbox;
	u32 block[2];

	block[0] = get_unaligned_le32(src);
	block[1] = get_unaligned_le32(src + 4);
	if (ctx->key_meshing && ctx->block_count == 1024 / GOST28147_BLOCK_SIZE) {
		crypto_gost28147_key_mesh_cryptopro(kp, sbox);
		crypto_gost28147_encrypt(kp, sbox, block, block);
		ctx->block_count = 0;
	}

	crypto_gost28147_encrypt(kp, sbox, block, block);
	put_unaligned_le32(block[0], dst);
	put_unaligned_le32(block[1], dst + 4);
	ctx->block_count++;
}

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
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
#else
static int gost28147_cfb_encrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
			 struct scatterlist *src, unsigned int nbytes)
{
	struct crypto_tfm *tfm = crypto_blkcipher_ctx(desc->tfm);
	struct blkcipher_walk walk;
	unsigned int bsize = GOST28147_BLOCK_SIZE;
	int err;

	blkcipher_walk_init(&walk, dst, src, nbytes);
	err = blkcipher_walk_virt_block(desc, &walk, GOST28147_BLOCK_SIZE);

	while (walk.nbytes >= bsize) {
		if (walk.src.virt.addr == walk.dst.virt.addr)
			err = gost28147_cfb_encrypt_inplace(&walk, tfm);
		else
			err = gost28147_cfb_encrypt_segment(&walk, tfm);
		err = blkcipher_walk_done(desc, &walk, err);
	}

	if (walk.nbytes) {
		gost28147_cfb_final(&walk, tfm);
		err = blkcipher_walk_done(desc, &walk, 0);
	}

	return err;
}
#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
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
#else
static int gost28147_cfb_decrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
			 struct scatterlist *src, unsigned int nbytes)
{
	struct crypto_tfm *tfm = crypto_blkcipher_ctx(desc->tfm);
	struct blkcipher_walk walk;
	unsigned int bsize = GOST28147_BLOCK_SIZE;
	int err;

	blkcipher_walk_init(&walk, dst, src, nbytes);
	err = blkcipher_walk_virt_block(desc, &walk, GOST28147_BLOCK_SIZE);

	while (walk.nbytes >= bsize) {
		if (walk.src.virt.addr == walk.dst.virt.addr)
			err = gost28147_cfb_decrypt_inplace(&walk, tfm);
		else
			err = gost28147_cfb_decrypt_segment(&walk, tfm);
		err = blkcipher_walk_done(desc, &walk, err);
	}

	if (walk.nbytes) {
		gost28147_cfb_final(&walk, tfm);
		err = blkcipher_walk_done(desc, &walk, 0);
	}

	return err;
}
#endif

static void gost28147_cnt_single(struct crypto_skcipher *tfm,
		u8 *src, u8 *dst)
{
	struct crypto_gost28147_mode_ctx *ctx = crypto_skcipher_ctx(tfm);
	u32 *kp = ctx->ctx.key;
	const u32 *sbox = ctx->ctx.sbox;
	u32 block[2];
	u32 temp;

	block[0] = get_unaligned_le32(src);
	block[1] = get_unaligned_le32(src + 4);
	if (ctx->block_count == 0)
		crypto_gost28147_encrypt(kp, sbox, block, block);
	else if (ctx->key_meshing && ctx->block_count == 1024 / GOST28147_BLOCK_SIZE) {
		crypto_gost28147_key_mesh_cryptopro(kp, sbox);
		crypto_gost28147_encrypt(kp, sbox, block, block);
		ctx->block_count = 0;
	}

	block[0] += 0x01010101;
	temp = block[1] + 0x01010104;
	if (temp < block[1])
		block[1] = temp + 1; /* Overflow */
	else
		block[1] = temp;

	put_unaligned_le32(block[0], src);
	put_unaligned_le32(block[1], src + 4);

	crypto_gost28147_encrypt(kp, sbox, block, block);
	put_unaligned_le32(block[0], dst);
	put_unaligned_le32(block[1], dst + 4);
	ctx->block_count++;
}

/* final encrypt and decrypt is the same */
static void gost28147_cnt_final(struct skcipher_walk *walk,
			     struct crypto_skcipher *tfm)
{
	u8 tmp[GOST28147_BLOCK_SIZE];
	u8 *src = walk->src.virt.addr;
	u8 *dst = walk->dst.virt.addr;
	u8 *iv = walk->iv;
	unsigned int nbytes = walk->nbytes;

	gost28147_cnt_single(tfm, iv, tmp);
	crypto_xor_cpy(dst, tmp, src, nbytes);
}

static int gost28147_cnt_crypt_segment(struct skcipher_walk *walk,
				      struct crypto_skcipher *tfm)
{
	const unsigned int bsize = GOST28147_BLOCK_SIZE;
	unsigned int nbytes = walk->nbytes;
	u8 *src = walk->src.virt.addr;
	u8 *dst = walk->dst.virt.addr;
	u8 *iv = walk->iv;

	do {
		gost28147_cnt_single(tfm, iv, dst);
		crypto_xor(dst, src, bsize);

		src += bsize;
		dst += bsize;
	} while ((nbytes -= bsize) >= bsize);

	return nbytes;
}

static int gost28147_cnt_crypt_inplace(struct skcipher_walk *walk,
				      struct crypto_skcipher *tfm)
{
	const unsigned int bsize = GOST28147_BLOCK_SIZE;
	unsigned int nbytes = walk->nbytes;
	u8 *src = walk->src.virt.addr;
	u8 *iv = walk->iv;
	u8 tmp[GOST28147_BLOCK_SIZE];

	do {
		gost28147_cnt_single(tfm, iv, tmp);
		crypto_xor(src, tmp, bsize);

		src += bsize;
	} while ((nbytes -= bsize) >= bsize);

	return nbytes;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
static int gost28147_cnt_crypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct skcipher_walk walk;
	unsigned int bsize = GOST28147_BLOCK_SIZE;
	int err;

	err = skcipher_walk_virt(&walk, req, false);

	while (walk.nbytes >= bsize) {
		if (walk.src.virt.addr == walk.dst.virt.addr)
			err = gost28147_cnt_crypt_inplace(&walk, tfm);
		else
			err = gost28147_cnt_crypt_segment(&walk, tfm);
		err = skcipher_walk_done(&walk, err);
	}

	if (walk.nbytes) {
		gost28147_cnt_final(&walk, tfm);
		err = skcipher_walk_done(&walk, 0);
	}

	return err;
}
#else
static int gost28147_cnt_crypt(struct blkcipher_desc *desc, struct scatterlist *dst,
			 struct scatterlist *src, unsigned int nbytes)
{
	struct crypto_tfm *tfm = crypto_blkcipher_ctx(desc->tfm);
	struct blkcipher_walk walk;
	unsigned int bsize = GOST28147_BLOCK_SIZE;
	int err;

	blkcipher_walk_init(&walk, dst, src, nbytes);
	err = blkcipher_walk_virt_block(desc, &walk, GOST28147_BLOCK_SIZE);

	while (walk.nbytes >= bsize) {
		if (walk.src.virt.addr == walk.dst.virt.addr)
			err = gost28147_cnt_crypt_inplace(&walk, tfm);
		else
			err = gost28147_cnt_crypt_segment(&walk, tfm);
		err = blkcipher_walk_done(desc, &walk, err);
	}

	if (walk.nbytes) {
		gost28147_cnt_final(&walk, tfm);
		err = blkcipher_walk_done(desc, &walk, 0);
	}

	return err;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
static struct skcipher_alg gost28147_mode_algs[] = { {
	.min_keysize	= GOST28147_KEY_SIZE,
	.max_keysize	= GOST28147_KEY_SIZE,
	.ivsize		= GOST28147_IV_SIZE,
	.chunksize	= GOST28147_BLOCK_SIZE,
	.setkey		= gost28147_mode_setkey_tc26z,
	.encrypt	= gost28147_cfb_encrypt,
	.decrypt	= gost28147_cfb_decrypt,
	.base		= {
		.cra_name	=	"cfb(gost28147-tc26z)",
		.cra_driver_name =	"cfb-gost28147-tc26z-generic",
		.cra_priority	=	100,
		.cra_blocksize	=	1,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
		.cra_module	=	THIS_MODULE,
	}
}, {
	.min_keysize	= GOST28147_KEY_SIZE,
	.max_keysize	= GOST28147_KEY_SIZE,
	.ivsize		= GOST28147_IV_SIZE,
	.chunksize	= GOST28147_BLOCK_SIZE,
	.setkey		= gost28147_mode_setkey_cpa,
	.encrypt	= gost28147_cfb_encrypt,
	.decrypt	= gost28147_cfb_decrypt,
	.base		= {
		.cra_name	=	"cfb(gost28147-cpa)",
		.cra_driver_name =	"cfb-gost28147-cpa-generic",
		.cra_priority	=	100,
		.cra_blocksize	=	1,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
		.cra_module	=	THIS_MODULE,
	}
}, {
	.min_keysize	= GOST28147_KEY_SIZE,
	.max_keysize	= GOST28147_KEY_SIZE,
	.ivsize		= GOST28147_IV_SIZE,
	.chunksize	= GOST28147_BLOCK_SIZE,
	.setkey		= gost28147_mode_setkey_cpb,
	.encrypt	= gost28147_cfb_encrypt,
	.decrypt	= gost28147_cfb_decrypt,
	.base		= {
		.cra_name	=	"cfb(gost28147-cpb)",
		.cra_driver_name =	"cfb-gost28147-cpb-generic",
		.cra_priority	=	100,
		.cra_blocksize	=	1,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
		.cra_module	=	THIS_MODULE,
	}
}, {
	.min_keysize	= GOST28147_KEY_SIZE,
	.max_keysize	= GOST28147_KEY_SIZE,
	.ivsize		= GOST28147_IV_SIZE,
	.chunksize	= GOST28147_BLOCK_SIZE,
	.setkey		= gost28147_mode_setkey_cpc,
	.encrypt	= gost28147_cfb_encrypt,
	.decrypt	= gost28147_cfb_decrypt,
	.base		= {
		.cra_name	=	"cfb(gost28147-cpc)",
		.cra_driver_name =	"cfb-gost28147-cpc-generic",
		.cra_priority	=	100,
		.cra_blocksize	=	1,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
		.cra_module	=	THIS_MODULE,
	}
}, {
	.min_keysize	= GOST28147_KEY_SIZE,
	.max_keysize	= GOST28147_KEY_SIZE,
	.ivsize		= GOST28147_IV_SIZE,
	.chunksize	= GOST28147_BLOCK_SIZE,
	.setkey		= gost28147_mode_setkey_cpd,
	.encrypt	= gost28147_cfb_encrypt,
	.decrypt	= gost28147_cfb_decrypt,
	.base		= {
		.cra_name	=	"cfb(gost28147-cpd)",
		.cra_driver_name =	"cfb-gost28147-cpd-generic",
		.cra_priority	=	100,
		.cra_blocksize	=	1,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
		.cra_module	=	THIS_MODULE,
	}
}, {
	.min_keysize	= GOST28147_KEY_SIZE,
	.max_keysize	= GOST28147_KEY_SIZE,
	.ivsize		= GOST28147_IV_SIZE,
	.chunksize	= GOST28147_BLOCK_SIZE,
	.setkey		= gost28147_mode_setkey_tc26z,
	.encrypt	= gost28147_cnt_crypt,
	.decrypt	= gost28147_cnt_crypt,
	.base		= {
		.cra_name	=	"cnt(gost28147-tc26z)",
		.cra_driver_name =	"cnt-gost28147-tc26z-generic",
		.cra_priority	=	100,
		.cra_blocksize	=	1,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
		.cra_module	=	THIS_MODULE,
	}
}, {
	.min_keysize	= GOST28147_KEY_SIZE,
	.max_keysize	= GOST28147_KEY_SIZE,
	.ivsize		= GOST28147_IV_SIZE,
	.chunksize	= GOST28147_BLOCK_SIZE,
	.setkey		= gost28147_mode_setkey_cpa,
	.encrypt	= gost28147_cnt_crypt,
	.decrypt	= gost28147_cnt_crypt,
	.base		= {
		.cra_name	=	"cnt(gost28147-cpa)",
		.cra_driver_name =	"cnt-gost28147-cpa-generic",
		.cra_priority	=	100,
		.cra_blocksize	=	1,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
		.cra_module	=	THIS_MODULE,
	}
}, {
	.min_keysize	= GOST28147_KEY_SIZE,
	.max_keysize	= GOST28147_KEY_SIZE,
	.ivsize		= GOST28147_IV_SIZE,
	.chunksize	= GOST28147_BLOCK_SIZE,
	.setkey		= gost28147_mode_setkey_cpb,
	.encrypt	= gost28147_cnt_crypt,
	.decrypt	= gost28147_cnt_crypt,
	.base		= {
		.cra_name	=	"cnt(gost28147-cpb)",
		.cra_driver_name =	"cnt-gost28147-cpb-generic",
		.cra_priority	=	100,
		.cra_blocksize	=	1,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
		.cra_module	=	THIS_MODULE,
	}
}, {
	.min_keysize	= GOST28147_KEY_SIZE,
	.max_keysize	= GOST28147_KEY_SIZE,
	.ivsize		= GOST28147_IV_SIZE,
	.chunksize	= GOST28147_BLOCK_SIZE,
	.setkey		= gost28147_mode_setkey_cpc,
	.encrypt	= gost28147_cnt_crypt,
	.decrypt	= gost28147_cnt_crypt,
	.base		= {
		.cra_name	=	"cnt(gost28147-cpc)",
		.cra_driver_name =	"cnt-gost28147-cpc-generic",
		.cra_priority	=	100,
		.cra_blocksize	=	1,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
		.cra_module	=	THIS_MODULE,
	}
}, {
	.min_keysize	= GOST28147_KEY_SIZE,
	.max_keysize	= GOST28147_KEY_SIZE,
	.ivsize		= GOST28147_IV_SIZE,
	.chunksize	= GOST28147_BLOCK_SIZE,
	.setkey		= gost28147_mode_setkey_cpd,
	.encrypt	= gost28147_cnt_crypt,
	.decrypt	= gost28147_cnt_crypt,
	.base		= {
		.cra_name	=	"cnt(gost28147-cpd)",
		.cra_driver_name =	"cnt-gost28147-cpd-generic",
		.cra_priority	=	100,
		.cra_blocksize	=	1,
		.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
		.cra_module	=	THIS_MODULE,
	}
} };

int __init gost28147_modes_init(void)
{
	return crypto_register_skciphers(gost28147_mode_algs, ARRAY_SIZE(gost28147_mode_algs));
}

void __exit gost28147_modes_fini(void)
{
	crypto_unregister_skciphers(gost28147_mode_algs, ARRAY_SIZE(gost28147_mode_algs));
}
#else
static struct crypto_alg gost28147_mode_algs[] = { {
	.cra_name	=	"cfb(gost28147-tc26z)",
	.cra_driver_name =	"cfb-gost28147-tc26z-generic",
	.cra_flags	=	CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_priority	=	100,
	.cra_blocksize	=	1,
	.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
	.cra_type	=	&crypto_blkcipher_type,
	.cra_module	=	THIS_MODULE,
	.cra_u		=	{
		.blkcipher	=	{
			.min_keysize	= GOST28147_KEY_SIZE,
			.max_keysize	= GOST28147_KEY_SIZE,
			.ivsize		= GOST28147_IV_SIZE,
			.setkey		= gost28147_mode_setkey_tc26z,
			.encrypt	= gost28147_cfb_encrypt,
			.decrypt	= gost28147_cfb_decrypt,
		}
	}
}, {
	.cra_name	=	"cfb(gost28147-cpa)",
	.cra_driver_name =	"cfb-gost28147-cpa-generic",
	.cra_flags	=	CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_priority	=	100,
	.cra_blocksize	=	1,
	.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
	.cra_type	=	&crypto_blkcipher_type,
	.cra_module	=	THIS_MODULE,
	.cra_u		=	{
		.blkcipher	=	{
			.min_keysize	= GOST28147_KEY_SIZE,
			.max_keysize	= GOST28147_KEY_SIZE,
			.ivsize		= GOST28147_IV_SIZE,
			.setkey		= gost28147_mode_setkey_cpa,
			.encrypt	= gost28147_cfb_encrypt,
			.decrypt	= gost28147_cfb_decrypt,
		}
	}
}, {
	.cra_name	=	"cfb(gost28147-cpb)",
	.cra_driver_name =	"cfb-gost28147-cpb-generic",
	.cra_flags	=	CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_priority	=	100,
	.cra_blocksize	=	1,
	.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
	.cra_type	=	&crypto_blkcipher_type,
	.cra_module	=	THIS_MODULE,
	.cra_u		=	{
		.blkcipher	=	{
			.min_keysize	= GOST28147_KEY_SIZE,
			.max_keysize	= GOST28147_KEY_SIZE,
			.ivsize		= GOST28147_IV_SIZE,
			.setkey		= gost28147_mode_setkey_cpb,
			.encrypt	= gost28147_cfb_encrypt,
			.decrypt	= gost28147_cfb_decrypt,
		}
	}
}, {
	.cra_name	=	"cfb(gost28147-cpc)",
	.cra_driver_name =	"cfb-gost28147-cpc-generic",
	.cra_flags	=	CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_priority	=	100,
	.cra_blocksize	=	1,
	.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
	.cra_type	=	&crypto_blkcipher_type,
	.cra_module	=	THIS_MODULE,
	.cra_u		=	{
		.blkcipher	=	{
			.min_keysize	= GOST28147_KEY_SIZE,
			.max_keysize	= GOST28147_KEY_SIZE,
			.ivsize		= GOST28147_IV_SIZE,
			.setkey		= gost28147_mode_setkey_cpc,
			.encrypt	= gost28147_cfb_encrypt,
			.decrypt	= gost28147_cfb_decrypt,
		}
	}
}, {
	.cra_name	=	"cfb(gost28147-cpd)",
	.cra_driver_name =	"cfb-gost28147-cpd-generic",
	.cra_flags	=	CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_priority	=	100,
	.cra_blocksize	=	1,
	.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
	.cra_type	=	&crypto_blkcipher_type,
	.cra_module	=	THIS_MODULE,
	.cra_u		=	{
		.blkcipher	=	{
			.min_keysize	= GOST28147_KEY_SIZE,
			.max_keysize	= GOST28147_KEY_SIZE,
			.ivsize		= GOST28147_IV_SIZE,
			.setkey		= gost28147_mode_setkey_cpd,
			.encrypt	= gost28147_cfb_encrypt,
			.decrypt	= gost28147_cfb_decrypt,
		}
	}
}, {
	.cra_name	=	"cnt(gost28147-tc26z)",
	.cra_driver_name =	"cnt-gost28147-tc26z-generic",
	.cra_flags	=	CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_priority	=	100,
	.cra_blocksize	=	1,
	.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
	.cra_type	=	&crypto_blkcipher_type,
	.cra_module	=	THIS_MODULE,
	.cra_u		=	{
		.blkcipher	=	{
			.min_keysize	= GOST28147_KEY_SIZE,
			.max_keysize	= GOST28147_KEY_SIZE,
			.ivsize		= GOST28147_IV_SIZE,
			.setkey		= gost28147_mode_setkey_tc26z,
			.encrypt	= gost28147_cnt_crypt,
			.decrypt	= gost28147_cnt_crypt,
		}
	}
}, {
	.cra_name	=	"cnt(gost28147-cpa)",
	.cra_driver_name =	"cnt-gost28147-cpa-generic",
	.cra_flags	=	CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_priority	=	100,
	.cra_blocksize	=	1,
	.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
	.cra_type	=	&crypto_blkcipher_type,
	.cra_module	=	THIS_MODULE,
	.cra_u		=	{
		.blkcipher	=	{
			.min_keysize	= GOST28147_KEY_SIZE,
			.max_keysize	= GOST28147_KEY_SIZE,
			.ivsize		= GOST28147_IV_SIZE,
			.setkey		= gost28147_mode_setkey_cpa,
			.encrypt	= gost28147_cnt_crypt,
			.decrypt	= gost28147_cnt_crypt,
		}
	}
}, {
	.cra_name	=	"cnt(gost28147-cpb)",
	.cra_driver_name =	"cnt-gost28147-cpb-generic",
	.cra_flags	=	CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_priority	=	100,
	.cra_blocksize	=	1,
	.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
	.cra_type	=	&crypto_blkcipher_type,
	.cra_module	=	THIS_MODULE,
	.cra_u		=	{
		.blkcipher	=	{
			.min_keysize	= GOST28147_KEY_SIZE,
			.max_keysize	= GOST28147_KEY_SIZE,
			.ivsize		= GOST28147_IV_SIZE,
			.setkey		= gost28147_mode_setkey_cpb,
			.encrypt	= gost28147_cnt_crypt,
			.decrypt	= gost28147_cnt_crypt,
		}
	}
}, {
	.cra_name	=	"cnt(gost28147-cpc)",
	.cra_driver_name =	"cnt-gost28147-cpc-generic",
	.cra_flags	=	CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_priority	=	100,
	.cra_blocksize	=	1,
	.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
	.cra_type	=	&crypto_blkcipher_type,
	.cra_module	=	THIS_MODULE,
	.cra_u		=	{
		.blkcipher	=	{
			.min_keysize	= GOST28147_KEY_SIZE,
			.max_keysize	= GOST28147_KEY_SIZE,
			.ivsize		= GOST28147_IV_SIZE,
			.setkey		= gost28147_mode_setkey_cpc,
			.encrypt	= gost28147_cnt_crypt,
			.decrypt	= gost28147_cnt_crypt,
		}
	}
}, {
	.cra_name	=	"cnt(gost28147-cpd)",
	.cra_driver_name =	"cnt-gost28147-cpd-generic",
	.cra_flags	=	CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_priority	=	100,
	.cra_blocksize	=	1,
	.cra_ctxsize	=	sizeof(struct crypto_gost28147_mode_ctx),
	.cra_type	=	&crypto_blkcipher_type,
	.cra_module	=	THIS_MODULE,
	.cra_u		=	{
		.blkcipher	=	{
			.min_keysize	= GOST28147_KEY_SIZE,
			.max_keysize	= GOST28147_KEY_SIZE,
			.ivsize		= GOST28147_IV_SIZE,
			.setkey		= gost28147_mode_setkey_cpd,
			.encrypt	= gost28147_cnt_crypt,
			.decrypt	= gost28147_cnt_crypt,
		}
	}
} };

int __init gost28147_modes_init(void)
{
	return crypto_register_algs(gost28147_mode_algs, ARRAY_SIZE(gost28147_mode_algs));
}

void __exit gost28147_modes_fini(void)
{
	crypto_unregister_algs(gost28147_mode_algs, ARRAY_SIZE(gost28147_mode_algs));
}
#endif
