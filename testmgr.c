/*
 * Algorithm testing framework and tests.
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2002 Jean-Francois Dive <jef@linuxbe.org>
 * Copyright (c) 2007 Nokia Siemens Networks
 * Copyright (c) 2008 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * Updated RFC4106 AES-GCM testing.
 *    Authors: Aidan O'Mahony (aidan.o.mahony@intel.com)
 *             Adrian Hoban <adrian.hoban@intel.com>
 *             Gabriele Paoloni <gabriele.paoloni@intel.com>
 *             Tadeusz Struk (tadeusz.struk@intel.com)
 *    Copyright (c) 2010, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/fips.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#include <crypto/internal/cipher.h>
MODULE_IMPORT_NS(CRYPTO_INTERNAL);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
#define CRYPTO_TFM_REQ_FORBID_WEAK_KEYS CRYPTO_TFM_REQ_WEAK_KEY
#endif

static bool notests;
module_param(notests, bool, 0644);
MODULE_PARM_DESC(notests, "disable crypto self-tests");

#include "testmgr.h"
#include "gost-test.h"

/*
 * Need slab memory for testing (size in number of pages).
 */
#define XBUFSIZE	8

/*
 * Indexes into the xbuf to simulate cross-page access.
 */
#define IDX1		32
#define IDX2		32400
#define IDX3		1511
#define IDX4		8193
#define IDX5		22222
#define IDX6		17101
#define IDX7		27333
#define IDX8		3000

/*
* Used by test_cipher()
*/
#define ENCRYPT 1
#define DECRYPT 0

struct cipher_test_suite {
	const struct cipher_testvec *vecs;
	unsigned int count;
};

struct hash_test_suite {
	const struct hash_testvec *vecs;
	unsigned int count;
};

#if 0
struct aead_test_suite {
	struct {
		const struct aead_testvec *vecs;
		unsigned int count;
	} enc, dec;
};

struct akcipher_test_suite {
	const struct akcipher_testvec *vecs;
	unsigned int count;
};

struct kpp_test_suite {
	const struct kpp_testvec *vecs;
	unsigned int count;
};
#endif

struct alg_test_desc {
	const char *alg;
	int (*test)(const struct alg_test_desc *desc, const char *driver,
		    u32 type, u32 mask);
	int fips_allowed;	/* set if alg is allowed in fips mode */

	union {
		struct cipher_test_suite cipher;
		struct hash_test_suite hash;
#if 0
		struct aead_test_suite aead;
		struct akcipher_test_suite akcipher;
		struct kpp_test_suite kpp;
#endif
	} suite;
};

static const unsigned int IDX[8] = {
	IDX1, IDX2, IDX3, IDX4, IDX5, IDX6, IDX7, IDX8 };

static void hexdump(unsigned char *buf, unsigned int len)
{
	print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET,
			16, 1,
			buf, len, false);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)

struct tcrypt_result {
	struct completion completion;
	int err;
};

static void tcrypt_complete(struct crypto_async_request *req, int err)
{
	struct tcrypt_result *res = req->data;

	if (err == -EINPROGRESS)
		return;

	res->err = err;
	complete(&res->completion);
}

static int wait_async_op(int ret, struct tcrypt_result *tr)
{
	if (ret == -EINPROGRESS || ret == -EBUSY) {
		wait_for_completion(&tr->completion);
		reinit_completion(&tr->completion);
		ret = tr->err;
	}
	return ret;
}

#define crypto_wait tcrypt_result
#define crypto_req_done tcrypt_complete
#define crypto_wait_req wait_async_op
#define crypto_init_wait(a) init_completion(&(a)->completion)

#endif

static int testmgr_alloc_buf(char *buf[XBUFSIZE])
{
	int i;

	for (i = 0; i < XBUFSIZE; i++) {
		buf[i] = (void *)__get_free_page(GFP_KERNEL);
		if (!buf[i])
			goto err_free_buf;
	}

	return 0;

err_free_buf:
	while (i-- > 0)
		free_page((unsigned long)buf[i]);

	return -ENOMEM;
}

static void testmgr_free_buf(char *buf[XBUFSIZE])
{
	int i;

	for (i = 0; i < XBUFSIZE; i++)
		free_page((unsigned long)buf[i]);
}

static int ahash_guard_result(char *result, char c, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		if (result[i] != c)
			return -EINVAL;
	}

	return 0;
}

static int ahash_partial_update(struct ahash_request **preq,
	struct crypto_ahash *tfm, const struct hash_testvec *template,
	void *hash_buff, int k, int temp, struct scatterlist *sg,
	const char *algo, char *result, struct crypto_wait *wait)
{
	char *state;
	struct ahash_request *req;
	int statesize, ret = -EINVAL;
	static const unsigned char guard[] = { 0x00, 0xba, 0xad, 0x00 };
	int digestsize = crypto_ahash_digestsize(tfm);

	req = *preq;
	statesize = crypto_ahash_statesize(
			crypto_ahash_reqtfm(req));
	state = kmalloc(statesize + sizeof(guard), GFP_KERNEL);
	if (!state) {
		pr_err("gost-alg: hash: Failed to alloc state for %s\n", algo);
		goto out_nostate;
	}
	memcpy(state + statesize, guard, sizeof(guard));
	memset(result, 1, digestsize);
	ret = crypto_ahash_export(req, state);
	WARN_ON(memcmp(state + statesize, guard, sizeof(guard)));
	if (ret) {
		pr_err("gost-alg: hash: Failed to export() for %s\n", algo);
		goto out;
	}
	ret = ahash_guard_result(result, 1, digestsize);
	if (ret) {
		pr_err("gost-alg: hash: Failed, export used req->result for %s\n",
		       algo);
		goto out;
	}
	ahash_request_free(req);
	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		pr_err("gost-alg: hash: Failed to alloc request for %s\n", algo);
		goto out_noreq;
	}
	ahash_request_set_callback(req,
		CRYPTO_TFM_REQ_MAY_BACKLOG,
		crypto_req_done, wait);

	memcpy(hash_buff, template->plaintext + temp,
		template->tap[k]);
	sg_init_one(&sg[0], hash_buff, template->tap[k]);
	ahash_request_set_crypt(req, sg, result, template->tap[k]);
	ret = crypto_ahash_import(req, state);
	if (ret) {
		pr_err("gost-alg: hash: Failed to import() for %s\n", algo);
		goto out;
	}
	ret = ahash_guard_result(result, 1, digestsize);
	if (ret) {
		pr_err("gost-alg: hash: Failed, import used req->result for %s\n",
		       algo);
		goto out;
	}
	ret = crypto_wait_req(crypto_ahash_update(req), wait);
	if (ret)
		goto out;
	*preq = req;
	ret = 0;
	goto out_noreq;
out:
	ahash_request_free(req);
out_noreq:
	kfree(state);
out_nostate:
	return ret;
}

static int __test_hash(struct crypto_ahash *tfm,
		       const struct hash_testvec *template, unsigned int tcount,
		       bool use_digest, const int align_offset)
{
	const char *algo = crypto_tfm_alg_driver_name(crypto_ahash_tfm(tfm));
	size_t digest_size = crypto_ahash_digestsize(tfm);
	unsigned int i, j, k, temp;
	struct scatterlist sg[8];
	char *result;
	char *key;
	struct ahash_request *req;
	struct crypto_wait wait;
	void *hash_buff;
	char *xbuf[XBUFSIZE];
	int ret = -ENOMEM;

	result = kmalloc(digest_size, GFP_KERNEL);
	if (!result)
		return ret;
	key = kmalloc(MAX_KEYLEN, GFP_KERNEL);
	if (!key)
		goto out_nobuf;
	if (testmgr_alloc_buf(xbuf))
		goto out_nobuf;

	crypto_init_wait(&wait);

	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		printk(KERN_ERR "gost-alg: hash: Failed to allocate request for "
		       "%s\n", algo);
		goto out_noreq;
	}
	ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				   crypto_req_done, &wait);

	j = 0;
	for (i = 0; i < tcount; i++) {
		if (template[i].np)
			continue;

		ret = -EINVAL;
		if (WARN_ON(align_offset + template[i].psize > PAGE_SIZE))
			goto out;

		j++;
		memset(result, 0, digest_size);

		hash_buff = xbuf[0];
		hash_buff += align_offset;

		memcpy(hash_buff, template[i].plaintext, template[i].psize);
		sg_init_one(&sg[0], hash_buff, template[i].psize);

		if (template[i].ksize) {
			crypto_ahash_clear_flags(tfm, ~0);
			if (template[i].ksize > MAX_KEYLEN) {
				pr_err("gost-alg: hash: setkey failed on test %d for %s: key size %d > %d\n",
				       j, algo, template[i].ksize, MAX_KEYLEN);
				ret = -EINVAL;
				goto out;
			}
			memcpy(key, template[i].key, template[i].ksize);
			ret = crypto_ahash_setkey(tfm, key, template[i].ksize);
			if (ret) {
				printk(KERN_ERR "gost-alg: hash: setkey failed on "
				       "test %d for %s: ret=%d\n", j, algo,
				       -ret);
				goto out;
			}
		}

		ahash_request_set_crypt(req, sg, result, template[i].psize);
		if (use_digest) {
			ret = crypto_wait_req(crypto_ahash_digest(req), &wait);
			if (ret) {
				pr_err("gost-alg: hash: digest failed on test %d "
				       "for %s: ret=%d\n", j, algo, -ret);
				goto out;
			}
		} else {
			memset(result, 1, digest_size);
			ret = crypto_wait_req(crypto_ahash_init(req), &wait);
			if (ret) {
				pr_err("gost-alg: hash: init failed on test %d "
				       "for %s: ret=%d\n", j, algo, -ret);
				goto out;
			}
			ret = ahash_guard_result(result, 1, digest_size);
			if (ret) {
				pr_err("gost-alg: hash: init failed on test %d "
				       "for %s: used req->result\n", j, algo);
				goto out;
			}
			ret = crypto_wait_req(crypto_ahash_update(req), &wait);
			if (ret) {
				pr_err("gost-alg: hash: update failed on test %d "
				       "for %s: ret=%d\n", j, algo, -ret);
				goto out;
			}
			ret = ahash_guard_result(result, 1, digest_size);
			if (ret) {
				pr_err("gost-alg: hash: update failed on test %d "
				       "for %s: used req->result\n", j, algo);
				goto out;
			}
			ret = crypto_wait_req(crypto_ahash_final(req), &wait);
			if (ret) {
				pr_err("gost-alg: hash: final failed on test %d "
				       "for %s: ret=%d\n", j, algo, -ret);
				goto out;
			}
		}

		if (memcmp(result, template[i].digest,
			   crypto_ahash_digestsize(tfm))) {
			printk(KERN_ERR "gost-alg: hash: Test %d failed for %s\n",
			       j, algo);
			hexdump(result, crypto_ahash_digestsize(tfm));
			ret = -EINVAL;
			goto out;
		}
	}

	j = 0;
	for (i = 0; i < tcount; i++) {
		/* alignment tests are only done with continuous buffers */
		if (align_offset != 0)
			break;

		if (!template[i].np)
			continue;

		j++;
		memset(result, 0, digest_size);

		temp = 0;
		sg_init_table(sg, template[i].np);
		ret = -EINVAL;
		for (k = 0; k < template[i].np; k++) {
			if (WARN_ON(offset_in_page(IDX[k]) +
				    template[i].tap[k] > PAGE_SIZE))
				goto out;
			sg_set_buf(&sg[k],
				   memcpy(xbuf[IDX[k] >> PAGE_SHIFT] +
					  offset_in_page(IDX[k]),
					  template[i].plaintext + temp,
					  template[i].tap[k]),
				   template[i].tap[k]);
			temp += template[i].tap[k];
		}

		if (template[i].ksize) {
			if (template[i].ksize > MAX_KEYLEN) {
				pr_err("gost-alg: hash: setkey failed on test %d for %s: key size %d > %d\n",
				       j, algo, template[i].ksize, MAX_KEYLEN);
				ret = -EINVAL;
				goto out;
			}
			crypto_ahash_clear_flags(tfm, ~0);
			memcpy(key, template[i].key, template[i].ksize);
			ret = crypto_ahash_setkey(tfm, key, template[i].ksize);

			if (ret) {
				printk(KERN_ERR "gost-alg: hash: setkey "
				       "failed on chunking test %d "
				       "for %s: ret=%d\n", j, algo, -ret);
				goto out;
			}
		}

		ahash_request_set_crypt(req, sg, result, template[i].psize);
		ret = crypto_wait_req(crypto_ahash_digest(req), &wait);
		if (ret) {
			pr_err("gost-alg: hash: digest failed on chunking test %d for %s: ret=%d\n",
			       j, algo, -ret);
			goto out;
		}

		if (memcmp(result, template[i].digest,
			   crypto_ahash_digestsize(tfm))) {
			printk(KERN_ERR "gost-alg: hash: Chunking test %d "
			       "failed for %s\n", j, algo);
			hexdump(result, crypto_ahash_digestsize(tfm));
			ret = -EINVAL;
			goto out;
		}
	}

	/* partial update exercise */
	j = 0;
	for (i = 0; i < tcount; i++) {
		/* alignment tests are only done with continuous buffers */
		if (align_offset != 0)
			break;

		if (template[i].np < 2)
			continue;

		j++;
		memset(result, 0, digest_size);

		ret = -EINVAL;
		hash_buff = xbuf[0];
		memcpy(hash_buff, template[i].plaintext,
			template[i].tap[0]);
		sg_init_one(&sg[0], hash_buff, template[i].tap[0]);

		if (template[i].ksize) {
			crypto_ahash_clear_flags(tfm, ~0);
			if (template[i].ksize > MAX_KEYLEN) {
				pr_err("gost-alg: hash: setkey failed on test %d for %s: key size %d > %d\n",
					j, algo, template[i].ksize, MAX_KEYLEN);
				ret = -EINVAL;
				goto out;
			}
			memcpy(key, template[i].key, template[i].ksize);
			ret = crypto_ahash_setkey(tfm, key, template[i].ksize);
			if (ret) {
				pr_err("gost-alg: hash: setkey failed on test %d for %s: ret=%d\n",
					j, algo, -ret);
				goto out;
			}
		}

		ahash_request_set_crypt(req, sg, result, template[i].tap[0]);
		ret = crypto_wait_req(crypto_ahash_init(req), &wait);
		if (ret) {
			pr_err("gost-alg: hash: init failed on test %d for %s: ret=%d\n",
				j, algo, -ret);
			goto out;
		}
		ret = crypto_wait_req(crypto_ahash_update(req), &wait);
		if (ret) {
			pr_err("gost-alg: hash: update failed on test %d for %s: ret=%d\n",
				j, algo, -ret);
			goto out;
		}

		temp = template[i].tap[0];
		for (k = 1; k < template[i].np; k++) {
			ret = ahash_partial_update(&req, tfm, &template[i],
				hash_buff, k, temp, &sg[0], algo, result,
				&wait);
			if (ret) {
				pr_err("gost-alg: hash: partial update failed on test %d for %s: ret=%d\n",
					j, algo, -ret);
				goto out_noreq;
			}
			temp += template[i].tap[k];
		}
		ret = crypto_wait_req(crypto_ahash_final(req), &wait);
		if (ret) {
			pr_err("gost-alg: hash: final failed on test %d for %s: ret=%d\n",
				j, algo, -ret);
			goto out;
		}
		if (memcmp(result, template[i].digest,
			   crypto_ahash_digestsize(tfm))) {
			pr_err("gost-alg: hash: Partial Test %d failed for %s\n",
			       j, algo);
			hexdump(result, crypto_ahash_digestsize(tfm));
			ret = -EINVAL;
			goto out;
		}
	}

	ret = 0;

out:
	ahash_request_free(req);
out_noreq:
	testmgr_free_buf(xbuf);
out_nobuf:
	kfree(key);
	kfree(result);
	return ret;
}

static int test_hash(struct crypto_ahash *tfm,
		     const struct hash_testvec *template,
		     unsigned int tcount, bool use_digest)
{
	unsigned int alignmask;
	int ret;

	ret = __test_hash(tfm, template, tcount, use_digest, 0);
	if (ret)
		return ret;

	/* test unaligned buffers, check with one byte offset */
	ret = __test_hash(tfm, template, tcount, use_digest, 1);
	if (ret)
		return ret;

	alignmask = crypto_tfm_alg_alignmask(&tfm->base);
	if (alignmask) {
		/* Check if alignment mask for tfm is correctly set. */
		ret = __test_hash(tfm, template, tcount, use_digest,
				  alignmask + 1);
		if (ret)
			return ret;
	}

	return 0;
}

#if 0
static int __test_aead(struct crypto_aead *tfm, int enc,
		       const struct aead_testvec *template, unsigned int tcount,
		       const bool diff_dst, const int align_offset)
{
	const char *algo = crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm));
	unsigned int i, j, k, n, temp;
	int ret = -ENOMEM;
	char *q;
	char *key;
	struct aead_request *req;
	struct scatterlist *sg;
	struct scatterlist *sgout;
	const char *e, *d;
	struct crypto_wait wait;
	unsigned int authsize, iv_len;
	void *input;
	void *output;
	void *assoc;
	char *iv;
	char *xbuf[XBUFSIZE];
	char *xoutbuf[XBUFSIZE];
	char *axbuf[XBUFSIZE];

	iv = kzalloc(MAX_IVLEN, GFP_KERNEL);
	if (!iv)
		return ret;
	key = kmalloc(MAX_KEYLEN, GFP_KERNEL);
	if (!key)
		goto out_noxbuf;
	if (testmgr_alloc_buf(xbuf))
		goto out_noxbuf;
	if (testmgr_alloc_buf(axbuf))
		goto out_noaxbuf;
	if (diff_dst && testmgr_alloc_buf(xoutbuf))
		goto out_nooutbuf;

	/* avoid "the frame size is larger than 1024 bytes" compiler warning */
	sg = kmalloc(sizeof(*sg) *  8 * (diff_dst ? 4 : 2),
		     GFP_KERNEL);
	if (!sg)
		goto out_nosg;
	sgout = &sg[16];

	if (diff_dst)
		d = "-ddst";
	else
		d = "";

	if (enc == ENCRYPT)
		e = "encryption";
	else
		e = "decryption";

	crypto_init_wait(&wait);

	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		pr_err("gost-alg: aead%s: Failed to allocate request for %s\n",
		       d, algo);
		goto out;
	}

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);

	iv_len = crypto_aead_ivsize(tfm);

	for (i = 0, j = 0; i < tcount; i++) {
		if (template[i].np)
			continue;

		j++;

		/* some templates have no input data but they will
		 * touch input
		 */
		input = xbuf[0];
		input += align_offset;
		assoc = axbuf[0];

		ret = -EINVAL;
		if (WARN_ON(align_offset + template[i].ilen >
			    PAGE_SIZE || template[i].alen > PAGE_SIZE))
			goto out;

		memcpy(input, template[i].input, template[i].ilen);
		memcpy(assoc, template[i].assoc, template[i].alen);
		if (template[i].iv)
			memcpy(iv, template[i].iv, iv_len);
		else
			memset(iv, 0, iv_len);

		crypto_aead_clear_flags(tfm, ~0);
		if (template[i].wk)
			crypto_aead_set_flags(tfm, CRYPTO_TFM_REQ_FORBID_WEAK_KEYS);

		if (template[i].klen > MAX_KEYLEN) {
			pr_err("gost-alg: aead%s: setkey failed on test %d for %s: key size %d > %d\n",
			       d, j, algo, template[i].klen,
			       MAX_KEYLEN);
			ret = -EINVAL;
			goto out;
		}
		memcpy(key, template[i].key, template[i].klen);

		ret = crypto_aead_setkey(tfm, key, template[i].klen);
		if (template[i].fail == !ret) {
			pr_err("gost-alg: aead%s: setkey failed on test %d for %s: flags=%x\n",
			       d, j, algo, crypto_aead_get_flags(tfm));
			goto out;
		} else if (ret)
			continue;

		authsize = abs(template[i].rlen - template[i].ilen);
		ret = crypto_aead_setauthsize(tfm, authsize);
		if (ret) {
			pr_err("gost-alg: aead%s: Failed to set authsize to %u on test %d for %s\n",
			       d, authsize, j, algo);
			goto out;
		}

		k = !!template[i].alen;
		sg_init_table(sg, k + 1);
		sg_set_buf(&sg[0], assoc, template[i].alen);
		sg_set_buf(&sg[k], input,
			   template[i].ilen + (enc ? authsize : 0));
		output = input;

		if (diff_dst) {
			sg_init_table(sgout, k + 1);
			sg_set_buf(&sgout[0], assoc, template[i].alen);

			output = xoutbuf[0];
			output += align_offset;
			sg_set_buf(&sgout[k], output,
				   template[i].rlen + (enc ? 0 : authsize));
		}

		aead_request_set_crypt(req, sg, (diff_dst) ? sgout : sg,
				       template[i].ilen, iv);

		aead_request_set_ad(req, template[i].alen);

		ret = crypto_wait_req(enc ? crypto_aead_encrypt(req)
				      : crypto_aead_decrypt(req), &wait);

		switch (ret) {
		case 0:
			if (template[i].novrfy) {
				/* verification was supposed to fail */
				pr_err("gost-alg: aead%s: %s failed on test %d for %s: ret was 0, expected -EBADMSG\n",
				       d, e, j, algo);
				/* so really, we got a bad message */
				ret = -EBADMSG;
				goto out;
			}
			break;
		case -EBADMSG:
			if (template[i].novrfy)
				/* verification failure was expected */
				continue;
			/* fall through */
		default:
			pr_err("gost-alg: aead%s: %s failed on test %d for %s: ret=%d\n",
			       d, e, j, algo, -ret);
			goto out;
		}

		q = output;
		if (memcmp(q, template[i].result, template[i].rlen)) {
			pr_err("gost-alg: aead%s: Test %d failed on %s for %s\n",
			       d, j, e, algo);
			hexdump(q, template[i].rlen);
			ret = -EINVAL;
			goto out;
		}
	}

	for (i = 0, j = 0; i < tcount; i++) {
		/* alignment tests are only done with continuous buffers */
		if (align_offset != 0)
			break;

		if (!template[i].np)
			continue;

		j++;

		if (template[i].iv)
			memcpy(iv, template[i].iv, iv_len);
		else
			memset(iv, 0, MAX_IVLEN);

		crypto_aead_clear_flags(tfm, ~0);
		if (template[i].wk)
			crypto_aead_set_flags(tfm, CRYPTO_TFM_REQ_FORBID_WEAK_KEYS);
		if (template[i].klen > MAX_KEYLEN) {
			pr_err("gost-alg: aead%s: setkey failed on test %d for %s: key size %d > %d\n",
			       d, j, algo, template[i].klen, MAX_KEYLEN);
			ret = -EINVAL;
			goto out;
		}
		memcpy(key, template[i].key, template[i].klen);

		ret = crypto_aead_setkey(tfm, key, template[i].klen);
		if (template[i].fail == !ret) {
			pr_err("gost-alg: aead%s: setkey failed on chunk test %d for %s: flags=%x\n",
			       d, j, algo, crypto_aead_get_flags(tfm));
			goto out;
		} else if (ret)
			continue;

		authsize = abs(template[i].rlen - template[i].ilen);

		ret = -EINVAL;
		sg_init_table(sg, template[i].anp + template[i].np);
		if (diff_dst)
			sg_init_table(sgout, template[i].anp + template[i].np);

		ret = -EINVAL;
		for (k = 0, temp = 0; k < template[i].anp; k++) {
			if (WARN_ON(offset_in_page(IDX[k]) +
				    template[i].atap[k] > PAGE_SIZE))
				goto out;
			sg_set_buf(&sg[k],
				   memcpy(axbuf[IDX[k] >> PAGE_SHIFT] +
					  offset_in_page(IDX[k]),
					  template[i].assoc + temp,
					  template[i].atap[k]),
				   template[i].atap[k]);
			if (diff_dst)
				sg_set_buf(&sgout[k],
					   axbuf[IDX[k] >> PAGE_SHIFT] +
					   offset_in_page(IDX[k]),
					   template[i].atap[k]);
			temp += template[i].atap[k];
		}

		for (k = 0, temp = 0; k < template[i].np; k++) {
			if (WARN_ON(offset_in_page(IDX[k]) +
				    template[i].tap[k] > PAGE_SIZE))
				goto out;

			q = xbuf[IDX[k] >> PAGE_SHIFT] + offset_in_page(IDX[k]);
			memcpy(q, template[i].input + temp, template[i].tap[k]);
			sg_set_buf(&sg[template[i].anp + k],
				   q, template[i].tap[k]);

			if (diff_dst) {
				q = xoutbuf[IDX[k] >> PAGE_SHIFT] +
				    offset_in_page(IDX[k]);

				memset(q, 0, template[i].tap[k]);

				sg_set_buf(&sgout[template[i].anp + k],
					   q, template[i].tap[k]);
			}

			n = template[i].tap[k];
			if (k == template[i].np - 1 && enc)
				n += authsize;
			if (offset_in_page(q) + n < PAGE_SIZE)
				q[n] = 0;

			temp += template[i].tap[k];
		}

		ret = crypto_aead_setauthsize(tfm, authsize);
		if (ret) {
			pr_err("gost-alg: aead%s: Failed to set authsize to %u on chunk test %d for %s\n",
			       d, authsize, j, algo);
			goto out;
		}

		if (enc) {
			if (WARN_ON(sg[template[i].anp + k - 1].offset +
				    sg[template[i].anp + k - 1].length +
				    authsize > PAGE_SIZE)) {
				ret = -EINVAL;
				goto out;
			}

			if (diff_dst)
				sgout[template[i].anp + k - 1].length +=
					authsize;
			sg[template[i].anp + k - 1].length += authsize;
		}

		aead_request_set_crypt(req, sg, (diff_dst) ? sgout : sg,
				       template[i].ilen,
				       iv);

		aead_request_set_ad(req, template[i].alen);

		ret = crypto_wait_req(enc ? crypto_aead_encrypt(req)
				      : crypto_aead_decrypt(req), &wait);

		switch (ret) {
		case 0:
			if (template[i].novrfy) {
				/* verification was supposed to fail */
				pr_err("gost-alg: aead%s: %s failed on chunk test %d for %s: ret was 0, expected -EBADMSG\n",
				       d, e, j, algo);
				/* so really, we got a bad message */
				ret = -EBADMSG;
				goto out;
			}
			break;
		case -EBADMSG:
			if (template[i].novrfy)
				/* verification failure was expected */
				continue;
			/* fall through */
		default:
			pr_err("gost-alg: aead%s: %s failed on chunk test %d for %s: ret=%d\n",
			       d, e, j, algo, -ret);
			goto out;
		}

		ret = -EINVAL;
		for (k = 0, temp = 0; k < template[i].np; k++) {
			if (diff_dst)
				q = xoutbuf[IDX[k] >> PAGE_SHIFT] +
				    offset_in_page(IDX[k]);
			else
				q = xbuf[IDX[k] >> PAGE_SHIFT] +
				    offset_in_page(IDX[k]);

			n = template[i].tap[k];
			if (k == template[i].np - 1)
				n += enc ? authsize : -authsize;

			if (memcmp(q, template[i].result + temp, n)) {
				pr_err("gost-alg: aead%s: Chunk test %d failed on %s at page %u for %s\n",
				       d, j, e, k, algo);
				hexdump(q, n);
				goto out;
			}

			q += n;
			if (k == template[i].np - 1 && !enc) {
				if (!diff_dst &&
					memcmp(q, template[i].input +
					      temp + n, authsize))
					n = authsize;
				else
					n = 0;
			} else {
				for (n = 0; offset_in_page(q + n) && q[n]; n++)
					;
			}
			if (n) {
				pr_err("gost-alg: aead%s: Result buffer corruption in chunk test %d on %s at page %u for %s: %u bytes:\n",
				       d, j, e, k, algo, n);
				hexdump(q, n);
				goto out;
			}

			temp += template[i].tap[k];
		}
	}

	ret = 0;

out:
	aead_request_free(req);
	kfree(sg);
out_nosg:
	if (diff_dst)
		testmgr_free_buf(xoutbuf);
out_nooutbuf:
	testmgr_free_buf(axbuf);
out_noaxbuf:
	testmgr_free_buf(xbuf);
out_noxbuf:
	kfree(key);
	kfree(iv);
	return ret;
}

static int test_aead(struct crypto_aead *tfm, int enc,
		     const struct aead_testvec *template, unsigned int tcount)
{
	unsigned int alignmask;
	int ret;

	/* test 'dst == src' case */
	ret = __test_aead(tfm, enc, template, tcount, false, 0);
	if (ret)
		return ret;

	/* test 'dst != src' case */
	ret = __test_aead(tfm, enc, template, tcount, true, 0);
	if (ret)
		return ret;

	/* test unaligned buffers, check with one byte offset */
	ret = __test_aead(tfm, enc, template, tcount, true, 1);
	if (ret)
		return ret;

	alignmask = crypto_tfm_alg_alignmask(&tfm->base);
	if (alignmask) {
		/* Check if alignment mask for tfm is correctly set. */
		ret = __test_aead(tfm, enc, template, tcount, true,
				  alignmask + 1);
		if (ret)
			return ret;
	}

	return 0;
}
#endif

static int test_cipher(struct crypto_cipher *tfm, int enc,
		       const struct cipher_testvec *template,
		       unsigned int tcount)
{
	const char *algo = crypto_tfm_alg_driver_name(crypto_cipher_tfm(tfm));
	unsigned int i, j, k;
	char *q;
	const char *e;
	const char *input, *result;
	void *data;
	char *xbuf[XBUFSIZE];
	int ret = -ENOMEM;

	if (testmgr_alloc_buf(xbuf))
		goto out_nobuf;

	if (enc == ENCRYPT)
	        e = "encryption";
	else
		e = "decryption";

	j = 0;
	for (i = 0; i < tcount; i++) {
		if (template[i].np)
			continue;

		if (fips_enabled && template[i].fips_skip)
			continue;

		input  = enc ? template[i].ptext : template[i].ctext;
		result = enc ? template[i].ctext : template[i].ptext;
		j++;

		ret = -EINVAL;
		if (WARN_ON(template[i].len > PAGE_SIZE))
			goto out;

		data = xbuf[0];
		memcpy(data, input, template[i].len);

		crypto_cipher_clear_flags(tfm, ~0);
		if (template[i].wk)
			crypto_cipher_set_flags(tfm, CRYPTO_TFM_REQ_FORBID_WEAK_KEYS);

		ret = crypto_cipher_setkey(tfm, template[i].key,
					   template[i].klen);
		if (template[i].fail == !ret) {
			printk(KERN_ERR "gost-alg: cipher: setkey failed "
			       "on test %d for %s: flags=%x\n", j,
			       algo, crypto_cipher_get_flags(tfm));
			goto out;
		} else if (ret)
			continue;

		for (k = 0; k < template[i].len;
		     k += crypto_cipher_blocksize(tfm)) {
			if (enc)
				crypto_cipher_encrypt_one(tfm, data + k,
							  data + k);
			else
				crypto_cipher_decrypt_one(tfm, data + k,
							  data + k);
		}

		q = data;
		if (memcmp(q, result, template[i].len)) {
			printk(KERN_ERR "gost-alg: cipher: Test %d failed "
			       "on %s for %s\n", j, e, algo);
			hexdump(q, template[i].len);
			ret = -EINVAL;
			goto out;
		}
	}

	ret = 0;

out:
	testmgr_free_buf(xbuf);
out_nobuf:
	return ret;
}

static int __test_skcipher(struct crypto_skcipher *tfm, int enc,
			   const struct cipher_testvec *template,
			   unsigned int tcount,
			   const bool diff_dst, const int align_offset)
{
	const char *algo =
		crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm));
	unsigned int i, j, k, n, temp;
	char *q;
	struct skcipher_request *req;
	struct scatterlist sg[8];
	struct scatterlist sgout[8];
	const char *e, *d;
	struct crypto_wait wait;
	const char *input, *result;
	void *data;
	char iv[MAX_IVLEN];
	char *xbuf[XBUFSIZE];
	char *xoutbuf[XBUFSIZE];
	int ret = -ENOMEM;
	unsigned int ivsize = crypto_skcipher_ivsize(tfm);

	if (testmgr_alloc_buf(xbuf))
		goto out_nobuf;

	if (diff_dst && testmgr_alloc_buf(xoutbuf))
		goto out_nooutbuf;

	if (diff_dst)
		d = "-ddst";
	else
		d = "";

	if (enc == ENCRYPT)
	        e = "encryption";
	else
		e = "decryption";

	crypto_init_wait(&wait);

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		pr_err("gost-alg: skcipher%s: Failed to allocate request for %s\n",
		       d, algo);
		goto out;
	}

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);

	j = 0;
	for (i = 0; i < tcount; i++) {
		if (template[i].np && !template[i].also_non_np)
			continue;

		if (fips_enabled && template[i].fips_skip)
			continue;

		if (template[i].iv && !(template[i].generates_iv && enc))
			memcpy(iv, template[i].iv, ivsize);
		else
			memset(iv, 0, MAX_IVLEN);

		input  = enc ? template[i].ptext : template[i].ctext;
		result = enc ? template[i].ctext : template[i].ptext;
		j++;
		ret = -EINVAL;
		if (WARN_ON(align_offset + template[i].len > PAGE_SIZE))
			goto out;

		data = xbuf[0];
		data += align_offset;
		memcpy(data, input, template[i].len);

		crypto_skcipher_clear_flags(tfm, ~0);
		if (template[i].wk)
			crypto_skcipher_set_flags(tfm,
						  CRYPTO_TFM_REQ_FORBID_WEAK_KEYS);

		ret = crypto_skcipher_setkey(tfm, template[i].key,
					     template[i].klen);
		if (template[i].fail == !ret) {
			pr_err("gost-alg: skcipher%s: setkey failed on test %d for %s: flags=%x\n",
			       d, j, algo, crypto_skcipher_get_flags(tfm));
			goto out;
		} else if (ret)
			continue;

		sg_init_one(&sg[0], data, template[i].len);
		if (diff_dst) {
			data = xoutbuf[0];
			data += align_offset;
			sg_init_one(&sgout[0], data, template[i].len);
		}

		skcipher_request_set_crypt(req, sg, (diff_dst) ? sgout : sg,
					   template[i].len, iv);
		ret = crypto_wait_req(enc ? crypto_skcipher_encrypt(req) :
				      crypto_skcipher_decrypt(req), &wait);

		if (ret) {
			pr_err("gost-alg: skcipher%s: %s failed on test %d for %s: ret=%d\n",
			       d, e, j, algo, -ret);
			goto out;
		}

		q = data;
		if (memcmp(q, result, template[i].len)) {
			pr_err("gost-alg: skcipher%s: Test %d failed (invalid result) on %s for %s\n",
			       d, j, e, algo);
			hexdump(q, template[i].len);
			ret = -EINVAL;
			goto out;
		}

		if (template[i].generates_iv && enc &&
		    memcmp(iv, template[i].iv, crypto_skcipher_ivsize(tfm))) {
			pr_err("gost-alg: skcipher%s: Test %d failed (invalid output IV) on %s for %s\n",
			       d, j, e, algo);
			hexdump(iv, crypto_skcipher_ivsize(tfm));
			ret = -EINVAL;
			goto out;
		}
	}

	j = 0;
	for (i = 0; i < tcount; i++) {
		/* alignment tests are only done with continuous buffers */
		if (align_offset != 0)
			break;

		if (!template[i].np)
			continue;

		if (fips_enabled && template[i].fips_skip)
			continue;

		if (template[i].iv && !(template[i].generates_iv && enc))
			memcpy(iv, template[i].iv, ivsize);
		else
			memset(iv, 0, MAX_IVLEN);

		input  = enc ? template[i].ptext : template[i].ctext;
		result = enc ? template[i].ctext : template[i].ptext;
		j++;
		crypto_skcipher_clear_flags(tfm, ~0);
		if (template[i].wk)
			crypto_skcipher_set_flags(tfm,
						  CRYPTO_TFM_REQ_FORBID_WEAK_KEYS);

		ret = crypto_skcipher_setkey(tfm, template[i].key,
					     template[i].klen);
		if (template[i].fail == !ret) {
			pr_err("gost-alg: skcipher%s: setkey failed on chunk test %d for %s: flags=%x\n",
			       d, j, algo, crypto_skcipher_get_flags(tfm));
			goto out;
		} else if (ret)
			continue;

		temp = 0;
		ret = -EINVAL;
		sg_init_table(sg, template[i].np);
		if (diff_dst)
			sg_init_table(sgout, template[i].np);
		for (k = 0; k < template[i].np; k++) {
			if (WARN_ON(offset_in_page(IDX[k]) +
				    template[i].tap[k] > PAGE_SIZE))
				goto out;

			q = xbuf[IDX[k] >> PAGE_SHIFT] + offset_in_page(IDX[k]);

			memcpy(q, input + temp, template[i].tap[k]);

			if (offset_in_page(q) + template[i].tap[k] < PAGE_SIZE)
				q[template[i].tap[k]] = 0;

			sg_set_buf(&sg[k], q, template[i].tap[k]);
			if (diff_dst) {
				q = xoutbuf[IDX[k] >> PAGE_SHIFT] +
				    offset_in_page(IDX[k]);

				sg_set_buf(&sgout[k], q, template[i].tap[k]);

				memset(q, 0, template[i].tap[k]);
				if (offset_in_page(q) +
				    template[i].tap[k] < PAGE_SIZE)
					q[template[i].tap[k]] = 0;
			}

			temp += template[i].tap[k];
		}

		skcipher_request_set_crypt(req, sg, (diff_dst) ? sgout : sg,
					   template[i].len, iv);

		ret = crypto_wait_req(enc ? crypto_skcipher_encrypt(req) :
				      crypto_skcipher_decrypt(req), &wait);

		if (ret) {
			pr_err("gost-alg: skcipher%s: %s failed on chunk test %d for %s: ret=%d\n",
			       d, e, j, algo, -ret);
			goto out;
		}

		temp = 0;
		ret = -EINVAL;
		for (k = 0; k < template[i].np; k++) {
			if (diff_dst)
				q = xoutbuf[IDX[k] >> PAGE_SHIFT] +
				    offset_in_page(IDX[k]);
			else
				q = xbuf[IDX[k] >> PAGE_SHIFT] +
				    offset_in_page(IDX[k]);

			if (memcmp(q, result + temp, template[i].tap[k])) {
				pr_err("gost-alg: skcipher%s: Chunk test %d failed on %s at page %u for %s\n",
				       d, j, e, k, algo);
				hexdump(q, template[i].tap[k]);
				goto out;
			}

			q += template[i].tap[k];
			for (n = 0; offset_in_page(q + n) && q[n]; n++)
				;
			if (n) {
				pr_err("gost-alg: skcipher%s: Result buffer corruption in chunk test %d on %s at page %u for %s: %u bytes:\n",
				       d, j, e, k, algo, n);
				hexdump(q, n);
				goto out;
			}
			temp += template[i].tap[k];
		}
	}

	ret = 0;

out:
	skcipher_request_free(req);
	if (diff_dst)
		testmgr_free_buf(xoutbuf);
out_nooutbuf:
	testmgr_free_buf(xbuf);
out_nobuf:
	return ret;
}

static int test_skcipher(struct crypto_skcipher *tfm, int enc,
			 const struct cipher_testvec *template,
			 unsigned int tcount)
{
	unsigned int alignmask;
	int ret;

	/* test 'dst == src' case */
	ret = __test_skcipher(tfm, enc, template, tcount, false, 0);
	if (ret)
		return ret;

	/* test 'dst != src' case */
	ret = __test_skcipher(tfm, enc, template, tcount, true, 0);
	if (ret)
		return ret;

	/* test unaligned buffers, check with one byte offset */
	ret = __test_skcipher(tfm, enc, template, tcount, true, 1);
	if (ret)
		return ret;

	alignmask = crypto_tfm_alg_alignmask(&tfm->base);
	if (alignmask) {
		/* Check if alignment mask for tfm is correctly set. */
		ret = __test_skcipher(tfm, enc, template, tcount, true,
				      alignmask + 1);
		if (ret)
			return ret;
	}

	return 0;
}

#if 0
static int alg_test_aead(const struct alg_test_desc *desc, const char *driver,
			 u32 type, u32 mask)
{
	struct crypto_aead *tfm;
	int err = 0;

	tfm = crypto_alloc_aead(driver, type, mask);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "gost-alg: aead: Failed to load transform for %s: "
		       "%ld\n", driver, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	if (desc->suite.aead.enc.vecs) {
		err = test_aead(tfm, ENCRYPT, desc->suite.aead.enc.vecs,
				desc->suite.aead.enc.count);
		if (err)
			goto out;
	}

	if (!err && desc->suite.aead.dec.vecs)
		err = test_aead(tfm, DECRYPT, desc->suite.aead.dec.vecs,
				desc->suite.aead.dec.count);

out:
	crypto_free_aead(tfm);
	return err;
}
#endif

static int alg_test_cipher(const struct alg_test_desc *desc,
			   const char *driver, u32 type, u32 mask)
{
	const struct cipher_test_suite *suite = &desc->suite.cipher;
	struct crypto_cipher *tfm;
	int err;

	tfm = crypto_alloc_cipher(driver, type, mask);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "gost-alg: cipher: Failed to load transform for "
		       "%s: %ld\n", driver, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	err = test_cipher(tfm, ENCRYPT, suite->vecs, suite->count);
	if (!err)
		err = test_cipher(tfm, DECRYPT, suite->vecs, suite->count);

	crypto_free_cipher(tfm);
	return err;
}

static int alg_test_skcipher(const struct alg_test_desc *desc,
			     const char *driver, u32 type, u32 mask)
{
	const struct cipher_test_suite *suite = &desc->suite.cipher;
	struct crypto_skcipher *tfm;
	int err;

	tfm = crypto_alloc_skcipher(driver, type, mask);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "gost-alg: skcipher: Failed to load transform for "
		       "%s: %ld\n", driver, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	err = test_skcipher(tfm, ENCRYPT, suite->vecs, suite->count);
	if (!err)
		err = test_skcipher(tfm, DECRYPT, suite->vecs, suite->count);

	crypto_free_skcipher(tfm);
	return err;
}

static int __alg_test_hash(const struct hash_testvec *template,
			   unsigned int tcount, const char *driver,
			   u32 type, u32 mask)
{
	struct crypto_ahash *tfm;
	int err;

	tfm = crypto_alloc_ahash(driver, type, mask);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "gost-alg: hash: Failed to load transform for %s: "
		       "%ld\n", driver, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	err = test_hash(tfm, template, tcount, true);
	if (!err)
		err = test_hash(tfm, template, tcount, false);
	crypto_free_ahash(tfm);
	return err;
}

static int alg_test_hash(const struct alg_test_desc *desc, const char *driver,
			 u32 type, u32 mask)
{
	const struct hash_testvec *template = desc->suite.hash.vecs;
	unsigned int tcount = desc->suite.hash.count;
	unsigned int nr_unkeyed, nr_keyed;
	int err;

	/*
	 * For OPTIONAL_KEY algorithms, we have to do all the unkeyed tests
	 * first, before setting a key on the tfm.  To make this easier, we
	 * require that the unkeyed test vectors (if any) are listed first.
	 */

	for (nr_unkeyed = 0; nr_unkeyed < tcount; nr_unkeyed++) {
		if (template[nr_unkeyed].ksize)
			break;
	}
	for (nr_keyed = 0; nr_unkeyed + nr_keyed < tcount; nr_keyed++) {
		if (!template[nr_unkeyed + nr_keyed].ksize) {
			pr_err("gost-alg: hash: test vectors for %s out of order, "
			       "unkeyed ones must come first\n", desc->alg);
			return -EINVAL;
		}
	}

	err = 0;
	if (nr_unkeyed) {
		err = __alg_test_hash(template, nr_unkeyed, driver, type, mask);
		template += nr_unkeyed;
	}

	if (!err && nr_keyed)
		err = __alg_test_hash(template, nr_keyed, driver, type, mask);

	return err;
}

#if 0
static int do_test_kpp(struct crypto_kpp *tfm, const struct kpp_testvec *vec,
		       const char *alg)
{
	struct kpp_request *req;
	void *input_buf = NULL;
	void *output_buf = NULL;
	void *a_public = NULL;
	void *a_ss = NULL;
	void *shared_secret = NULL;
	struct crypto_wait wait;
	unsigned int out_len_max;
	int err = -ENOMEM;
	struct scatterlist src, dst;

	req = kpp_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		return err;

	crypto_init_wait(&wait);

	err = crypto_kpp_set_secret(tfm, vec->secret, vec->secret_size);
	if (err < 0)
		goto free_req;

	out_len_max = crypto_kpp_maxsize(tfm);
	output_buf = kzalloc(out_len_max, GFP_KERNEL);
	if (!output_buf) {
		err = -ENOMEM;
		goto free_req;
	}

	/* Use appropriate parameter as base */
	kpp_request_set_input(req, NULL, 0);
	sg_init_one(&dst, output_buf, out_len_max);
	kpp_request_set_output(req, &dst, out_len_max);
	kpp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				 crypto_req_done, &wait);

	/* Compute party A's public key */
	err = crypto_wait_req(crypto_kpp_generate_public_key(req), &wait);
	if (err) {
		pr_err("gost-alg: %s: Party A: generate public key test failed. err %d\n",
		       alg, err);
		goto free_output;
	}

	if (vec->genkey) {
		/* Save party A's public key */
		a_public = kzalloc(out_len_max, GFP_KERNEL);
		if (!a_public) {
			err = -ENOMEM;
			goto free_output;
		}
		memcpy(a_public, sg_virt(req->dst), out_len_max);
	} else {
		/* Verify calculated public key */
		if (memcmp(vec->expected_a_public, sg_virt(req->dst),
			   vec->expected_a_public_size)) {
			pr_err("gost-alg: %s: Party A: generate public key test failed. Invalid output\n",
			       alg);
			err = -EINVAL;
			goto free_output;
		}
	}

	/* Calculate shared secret key by using counter part (b) public key. */
	input_buf = kzalloc(vec->b_public_size, GFP_KERNEL);
	if (!input_buf) {
		err = -ENOMEM;
		goto free_output;
	}

	memcpy(input_buf, vec->b_public, vec->b_public_size);
	sg_init_one(&src, input_buf, vec->b_public_size);
	sg_init_one(&dst, output_buf, out_len_max);
	kpp_request_set_input(req, &src, vec->b_public_size);
	kpp_request_set_output(req, &dst, out_len_max);
	kpp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				 crypto_req_done, &wait);
	err = crypto_wait_req(crypto_kpp_compute_shared_secret(req), &wait);
	if (err) {
		pr_err("gost-alg: %s: Party A: compute shared secret test failed. err %d\n",
		       alg, err);
		goto free_all;
	}

	if (vec->genkey) {
		/* Save the shared secret obtained by party A */
		a_ss = kzalloc(vec->expected_ss_size, GFP_KERNEL);
		if (!a_ss) {
			err = -ENOMEM;
			goto free_all;
		}
		memcpy(a_ss, sg_virt(req->dst), vec->expected_ss_size);

		/*
		 * Calculate party B's shared secret by using party A's
		 * public key.
		 */
		err = crypto_kpp_set_secret(tfm, vec->b_secret,
					    vec->b_secret_size);
		if (err < 0)
			goto free_all;

		sg_init_one(&src, a_public, vec->expected_a_public_size);
		sg_init_one(&dst, output_buf, out_len_max);
		kpp_request_set_input(req, &src, vec->expected_a_public_size);
		kpp_request_set_output(req, &dst, out_len_max);
		kpp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
					 crypto_req_done, &wait);
		err = crypto_wait_req(crypto_kpp_compute_shared_secret(req),
				      &wait);
		if (err) {
			pr_err("gost-alg: %s: Party B: compute shared secret failed. err %d\n",
			       alg, err);
			goto free_all;
		}

		shared_secret = a_ss;
	} else {
		shared_secret = (void *)vec->expected_ss;
	}

	/*
	 * verify shared secret from which the user will derive
	 * secret key by executing whatever hash it has chosen
	 */
	if (memcmp(shared_secret, sg_virt(req->dst),
		   vec->expected_ss_size)) {
		pr_err("gost-alg: %s: compute shared secret test failed. Invalid output\n",
		       alg);
		err = -EINVAL;
	}

free_all:
	kfree(a_ss);
	kfree(input_buf);
free_output:
	kfree(a_public);
	kfree(output_buf);
free_req:
	kpp_request_free(req);
	return err;
}

static int test_kpp(struct crypto_kpp *tfm, const char *alg,
		    const struct kpp_testvec *vecs, unsigned int tcount)
{
	int ret, i;

	for (i = 0; i < tcount; i++) {
		ret = do_test_kpp(tfm, vecs++, alg);
		if (ret) {
			pr_err("gost-alg: %s: test failed on vector %d, err=%d\n",
			       alg, i + 1, ret);
			return ret;
		}
	}
	return 0;
}

static int alg_test_kpp(const struct alg_test_desc *desc, const char *driver,
			u32 type, u32 mask)
{
	struct crypto_kpp *tfm;
	int err = 0;

	tfm = crypto_alloc_kpp(driver, type, mask);
	if (IS_ERR(tfm)) {
		pr_err("gost-alg: kpp: Failed to load tfm for %s: %ld\n",
		       driver, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	if (desc->suite.kpp.vecs)
		err = test_kpp(tfm, desc->alg, desc->suite.kpp.vecs,
			       desc->suite.kpp.count);

	crypto_free_kpp(tfm);
	return err;
}

static int test_akcipher_one(struct crypto_akcipher *tfm,
			     const struct akcipher_testvec *vecs)
{
	char *xbuf[XBUFSIZE];
	struct akcipher_request *req;
	void *outbuf_enc = NULL;
	void *outbuf_dec = NULL;
	struct crypto_wait wait;
	unsigned int out_len_max, out_len = 0;
	int err = -ENOMEM;
	struct scatterlist src, dst, src_tab[2];

	if (testmgr_alloc_buf(xbuf))
		return err;

	req = akcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		goto free_xbuf;

	crypto_init_wait(&wait);

	if (vecs->public_key_vec)
		err = crypto_akcipher_set_pub_key(tfm, vecs->key,
						  vecs->key_len);
	else
		err = crypto_akcipher_set_priv_key(tfm, vecs->key,
						   vecs->key_len);
	if (err)
		goto free_req;

	err = -ENOMEM;
	out_len_max = crypto_akcipher_maxsize(tfm);
	outbuf_enc = kzalloc(out_len_max, GFP_KERNEL);
	if (!outbuf_enc)
		goto free_req;

	if (WARN_ON(vecs->m_size > PAGE_SIZE))
		goto free_all;

	memcpy(xbuf[0], vecs->m, vecs->m_size);

	sg_init_table(src_tab, 2);
	sg_set_buf(&src_tab[0], xbuf[0], 8);
	sg_set_buf(&src_tab[1], xbuf[0] + 8, vecs->m_size - 8);
	sg_init_one(&dst, outbuf_enc, out_len_max);
	akcipher_request_set_crypt(req, src_tab, &dst, vecs->m_size,
				   out_len_max);
	akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);

	err = crypto_wait_req(vecs->siggen_sigver_test ?
			      /* Run asymmetric signature generation */
			      crypto_akcipher_sign(req) :
			      /* Run asymmetric encrypt */
			      crypto_akcipher_encrypt(req), &wait);
	if (err) {
		pr_err("gost-alg: akcipher: encrypt test failed. err %d\n", err);
		goto free_all;
	}
	if (req->dst_len != vecs->c_size) {
		pr_err("gost-alg: akcipher: encrypt test failed. Invalid output len\n");
		err = -EINVAL;
		goto free_all;
	}
	/* verify that encrypted message is equal to expected */
	if (memcmp(vecs->c, outbuf_enc, vecs->c_size)) {
		pr_err("gost-alg: akcipher: encrypt test failed. Invalid output\n");
		hexdump(outbuf_enc, vecs->c_size);
		err = -EINVAL;
		goto free_all;
	}
	/* Don't invoke decrypt for vectors with public key */
	if (vecs->public_key_vec) {
		err = 0;
		goto free_all;
	}
	outbuf_dec = kzalloc(out_len_max, GFP_KERNEL);
	if (!outbuf_dec) {
		err = -ENOMEM;
		goto free_all;
	}

	if (WARN_ON(vecs->c_size > PAGE_SIZE))
		goto free_all;

	memcpy(xbuf[0], vecs->c, vecs->c_size);

	sg_init_one(&src, xbuf[0], vecs->c_size);
	sg_init_one(&dst, outbuf_dec, out_len_max);
	crypto_init_wait(&wait);
	akcipher_request_set_crypt(req, &src, &dst, vecs->c_size, out_len_max);

	err = crypto_wait_req(vecs->siggen_sigver_test ?
			      /* Run asymmetric signature verification */
			      crypto_akcipher_verify(req) :
			      /* Run asymmetric decrypt */
			      crypto_akcipher_decrypt(req), &wait);
	if (err) {
		pr_err("gost-alg: akcipher: decrypt test failed. err %d\n", err);
		goto free_all;
	}
	out_len = req->dst_len;
	if (out_len < vecs->m_size) {
		pr_err("gost-alg: akcipher: decrypt test failed. "
		       "Invalid output len %u\n", out_len);
		err = -EINVAL;
		goto free_all;
	}
	/* verify that decrypted message is equal to the original msg */
	if (memchr_inv(outbuf_dec, 0, out_len - vecs->m_size) ||
	    memcmp(vecs->m, outbuf_dec + out_len - vecs->m_size,
		   vecs->m_size)) {
		pr_err("gost-alg: akcipher: decrypt test failed. Invalid output\n");
		hexdump(outbuf_dec, out_len);
		err = -EINVAL;
	}
free_all:
	kfree(outbuf_dec);
	kfree(outbuf_enc);
free_req:
	akcipher_request_free(req);
free_xbuf:
	testmgr_free_buf(xbuf);
	return err;
}

static int test_akcipher(struct crypto_akcipher *tfm, const char *alg,
			 const struct akcipher_testvec *vecs,
			 unsigned int tcount)
{
	const char *algo =
		crypto_tfm_alg_driver_name(crypto_akcipher_tfm(tfm));
	int ret, i;

	for (i = 0; i < tcount; i++) {
		ret = test_akcipher_one(tfm, vecs++);
		if (!ret)
			continue;

		pr_err("gost-alg: akcipher: test %d failed for %s, err=%d\n",
		       i + 1, algo, ret);
		return ret;
	}
	return 0;
}

static int alg_test_akcipher(const struct alg_test_desc *desc,
			     const char *driver, u32 type, u32 mask)
{
	struct crypto_akcipher *tfm;
	int err = 0;

	tfm = crypto_alloc_akcipher(driver, type, mask);
	if (IS_ERR(tfm)) {
		pr_err("gost-alg: akcipher: Failed to load tfm for %s: %ld\n",
		       driver, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	if (desc->suite.akcipher.vecs)
		err = test_akcipher(tfm, desc->alg, desc->suite.akcipher.vecs,
				    desc->suite.akcipher.count);

	crypto_free_akcipher(tfm);
	return err;
}

static int alg_test_null(const struct alg_test_desc *desc,
			     const char *driver, u32 type, u32 mask)
{
	return 0;
}
#endif

#define __VECS(tv)	{ .vecs = tv, .count = ARRAY_SIZE(tv) }

/* Please keep this list sorted by algorithm name. */
static const struct alg_test_desc alg_test_descs[] = {
	{
		.alg = "cfb(gost28147-cpa)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = __VECS(gost28147_cpa_cfb_tv_template)
		}
	},
	{
		.alg = "cfb(gost28147-cpb)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = __VECS(gost28147_cpb_cfb_tv_template)
		}
	},
	{
		.alg = "cfb(gost28147-cpc)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = __VECS(gost28147_cpc_cfb_tv_template)
		}
	},
	{
		.alg = "cfb(gost28147-cpd)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = __VECS(gost28147_cpd_cfb_tv_template)
		}
	},
	{
		.alg = "cfb(gost28147-tc26z)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = __VECS(gost28147_tc26z_cfb_tv_template)
		}
	},
	{
		.alg = "cmac(kuznyechik)",
		.test = alg_test_hash,
		.suite = {
			.hash = __VECS(cmac_kuznyechik_tv_template)
		}
	},
	{
		.alg = "cmac(magma)",
		.test = alg_test_hash,
		.suite = {
			.hash = __VECS(cmac_magma_tv_template)
		}
	},
	{
		.alg = "cnt(gost28147-cpa)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = __VECS(gost28147_cpa_cnt_tv_template)
		}
	},
	{
		.alg = "cnt(gost28147-cpb)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = __VECS(gost28147_cpb_cnt_tv_template)
		}
	},
	{
		.alg = "cnt(gost28147-cpc)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = __VECS(gost28147_cpc_cnt_tv_template)
		}
	},
	{
		.alg = "cnt(gost28147-cpd)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = __VECS(gost28147_cpd_cnt_tv_template)
		}
	},
	{
		.alg = "cnt(gost28147-tc26z)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = __VECS(gost28147_tc26z_cnt_tv_template)
		}
	},
	{
		.alg = "ecb(gost28147-cpa)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = __VECS(gost28147_cpa_tv_template)
		}
	},
	{
		.alg = "ecb(gost28147-cpb)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = __VECS(gost28147_cpb_tv_template)
		}
	},
	{
		.alg = "ecb(gost28147-cpc)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = __VECS(gost28147_cpc_tv_template)
		}
	},
	{
		.alg = "ecb(gost28147-cpd)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = __VECS(gost28147_cpd_tv_template)
		}
	},
	{
		.alg = "ecb(gost28147-tc26z)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = __VECS(gost28147_tc26z_tv_template)
		}
	},
	{
		.alg = "ecb(kuznyechik)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = __VECS(kuznyechik_tv_template)
		}
	},
	{
		.alg = "ecb(magma)",
		.test = alg_test_skcipher,
		.suite = {
			.cipher = __VECS(magma_tv_template)
		}
	},
	{
		.alg = "gost28147imit-cpa",
		.test = alg_test_hash,
		.suite = {
			.hash = __VECS(gost28147imit_cpa_tv_template)
		}
	},
	{
		.alg = "gost28147imit-cpb",
		.test = alg_test_hash,
		.suite = {
			.hash = __VECS(gost28147imit_cpb_tv_template)
		}
	},
	{
		.alg = "gost28147imit-cpc",
		.test = alg_test_hash,
		.suite = {
			.hash = __VECS(gost28147imit_cpc_tv_template)
		}
	},
	{
		.alg = "gost28147imit-cpd",
		.test = alg_test_hash,
		.suite = {
			.hash = __VECS(gost28147imit_cpd_tv_template)
		}
	},
	{
		.alg = "gost28147imit-tc26z",
		.test = alg_test_hash,
		.suite = {
			.hash = __VECS(gost28147imit_tc26z_tv_template)
		}
	},
	{
		.alg = "gosthash94",
		.test = alg_test_hash,
		.suite = {
			.hash = __VECS(gosthash94_tv_template)
		}
	},
	{
		.alg = "hmac(gosthash94)",
		.test = alg_test_hash,
		.suite = {
			.hash = __VECS(hmac_gosthash94_tv_template)
		}
	},
	{
		.alg = "hmac(streebog256)",
		.test = alg_test_hash,
		.suite = {
			.hash = __VECS(hmac_streebog256_tv_template)
		}
	},
	{
		.alg = "hmac(streebog512)",
		.test = alg_test_hash,
		.suite = {
			.hash = __VECS(hmac_streebog512_tv_template)
		}
	},
	{
		.alg = "streebog256",
		.test = alg_test_hash,
		.suite = {
			.hash = __VECS(streebog_256_tv_template)
		}
	},
	{
		.alg = "streebog512",
		.test = alg_test_hash,
		.suite = {
			.hash = __VECS(streebog_512_tv_template)
		}
	},
};

static bool alg_test_descs_checked;

static void alg_test_descs_check_order(void)
{
	int i;

	/* only check once */
	if (alg_test_descs_checked)
		return;

	alg_test_descs_checked = true;

	for (i = 1; i < ARRAY_SIZE(alg_test_descs); i++) {
		int diff = strcmp(alg_test_descs[i - 1].alg,
				  alg_test_descs[i].alg);

		if (WARN_ON(diff > 0)) {
			pr_warn("testmgr: alg_test_descs entries in wrong order: '%s' before '%s'\n",
				alg_test_descs[i - 1].alg,
				alg_test_descs[i].alg);
		}

		if (WARN_ON(diff == 0)) {
			pr_warn("testmgr: duplicate alg_test_descs entry: '%s'\n",
				alg_test_descs[i].alg);
		}
	}
}

static int alg_find_test(const char *alg)
{
	int start = 0;
	int end = ARRAY_SIZE(alg_test_descs);

	while (start < end) {
		int i = (start + end) / 2;
		int diff = strcmp(alg_test_descs[i].alg, alg);

		if (diff > 0) {
			end = i;
			continue;
		}

		if (diff < 0) {
			start = i + 1;
			continue;
		}

		return i;
	}

	return -1;
}

int gost_alg_test(const char *driver, const char *alg, u32 type, u32 mask)
{
	int i;
	int j;
	int rc;

	if (!fips_enabled && notests) {
		printk_once(KERN_INFO "gost-alg: self-tests disabled\n");
		return 0;
	}

	alg_test_descs_check_order();

	if ((type & CRYPTO_ALG_TYPE_MASK) == CRYPTO_ALG_TYPE_CIPHER) {
		char nalg[CRYPTO_MAX_ALG_NAME];

		if (snprintf(nalg, sizeof(nalg), "ecb(%s)", alg) >=
		    sizeof(nalg))
			return -ENAMETOOLONG;

		i = alg_find_test(nalg);
		if (i < 0)
			goto notest;

		if (fips_enabled && !alg_test_descs[i].fips_allowed)
			goto non_fips_alg;

		rc = alg_test_cipher(alg_test_descs + i, driver, type, mask);
		goto test_done;
	}

	i = alg_find_test(alg);
	j = alg_find_test(driver);
	if (i < 0 && j < 0)
		goto notest;

	if (fips_enabled && ((i >= 0 && !alg_test_descs[i].fips_allowed) ||
			     (j >= 0 && !alg_test_descs[j].fips_allowed)))
		goto non_fips_alg;

	rc = 0;
	if (i >= 0)
		rc |= alg_test_descs[i].test(alg_test_descs + i, driver,
					     type, mask);
	if (j >= 0 && j != i)
		rc |= alg_test_descs[j].test(alg_test_descs + j, driver,
					     type, mask);

test_done:
	if (rc)
		pr_err("%s: %s gost-alg self test failed!\n", driver, alg);
	else
		pr_info("gost-alg: self-tests for %s (%s) passed\n", driver, alg);

	return rc;

notest:
	printk(KERN_INFO "gost-alg: No test for %s (%s)\n", alg, driver);
	return 0;
non_fips_alg:
	return -EINVAL;
}
