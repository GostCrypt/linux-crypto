/*
 * Algorithm testing framework and tests.
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2002 Jean-Francois Dive <jef@linuxbe.org>
 * Copyright (c) 2007 Nokia Siemens Networks
 * Copyright (c) 2008 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * Updated RFC4106 AES-GCM testing. Some test vectors were taken from
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/
 * gcm/gcm-test-vectors.tar.gz
 *     Authors: Aidan O'Mahony (aidan.o.mahony@intel.com)
 *              Adrian Hoban <adrian.hoban@intel.com>
 *              Gabriele Paoloni <gabriele.paoloni@intel.com>
 *              Tadeusz Struk (tadeusz.struk@intel.com)
 *     Copyright (c) 2010, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */
#ifndef _CRYPTO_TESTMGR_H
#define _CRYPTO_TESTMGR_H

#include <linux/netlink.h>

#define MAX_DIGEST_SIZE		64
#define MAX_TAP			8

#define MAX_KEYLEN		160
#define MAX_IVLEN		32

struct hash_testvec {
	/* only used with keyed hash algorithms */
	const char *key;
	const char *plaintext;
	const char *digest;
	unsigned char tap[MAX_TAP];
	unsigned short psize;
	unsigned char np;
	unsigned char ksize;
};

/*
 * cipher_testvec:	structure to describe a symmetric cipher test
 * @key:	Pointer to key
 * @klen:	Length of @key in bytes
 * @iv:		Pointer to IV (optional for some ciphers)
 * @ptext:	Pointer to plaintext
 * @ctext:	Pointer to ciphertext
 * @len:	Length of @ptext and @ctext in bytes
 * @fail:	If set to one, the test need to fail
 * @wk:		Does the test need CRYPTO_TFM_REQ_WEAK_KEY
 * 		( e.g. test needs to fail due to a weak key )
 * @np: 	numbers of SG to distribute data in (from 1 to MAX_TAP)
 * @tap:	How to distribute data in @np SGs
 * @also_non_np: 	if set to 1, the test will be also done without
 * 			splitting data in @np SGs
 * @fips_skip:	Skip the test vector in FIPS mode
 * @generates_iv: Encryption should ignore the given IV, and output @iv.
 *		  Decryption takes @iv.  Needed for AES Keywrap ("kw(aes)").
 */
struct cipher_testvec {
	const char *key;
	const char *iv;
	const char *ptext;
	const char *ctext;
	unsigned short tap[MAX_TAP];
	int np;
	unsigned char also_non_np;
	bool fail;
	unsigned char wk; /* weak key flag */
	unsigned char klen;
	unsigned short len;
	bool fips_skip;
	bool generates_iv;
};

struct aead_testvec {
	const char *key;
	const char *iv;
	const char *input;
	const char *assoc;
	const char *result;
	unsigned char tap[MAX_TAP];
	unsigned char atap[MAX_TAP];
	int np;
	int anp;
	bool fail;
	unsigned char novrfy;	/* ccm dec verification failure expected */
	unsigned char wk; /* weak key flag */
	unsigned char klen;
	unsigned short ilen;
	unsigned short alen;
	unsigned short rlen;
};

struct cprng_testvec {
	const char *key;
	const char *dt;
	const char *v;
	const char *result;
	unsigned char klen;
	unsigned short dtlen;
	unsigned short vlen;
	unsigned short rlen;
	unsigned short loops;
};

struct drbg_testvec {
	const unsigned char *entropy;
	size_t entropylen;
	const unsigned char *entpra;
	const unsigned char *entprb;
	size_t entprlen;
	const unsigned char *addtla;
	const unsigned char *addtlb;
	size_t addtllen;
	const unsigned char *pers;
	size_t perslen;
	const unsigned char *expected;
	size_t expectedlen;
};

struct akcipher_testvec {
	const unsigned char *key;
	const unsigned char *m;
	const unsigned char *c;
	unsigned int key_len;
	unsigned int m_size;
	unsigned int c_size;
	bool public_key_vec;
	bool siggen_sigver_test;
};

struct kpp_testvec {
	const unsigned char *secret;
	const unsigned char *b_secret;
	const unsigned char *b_public;
	const unsigned char *expected_a_public;
	const unsigned char *expected_ss;
	unsigned short secret_size;
	unsigned short b_secret_size;
	unsigned short b_public_size;
	unsigned short expected_a_public_size;
	unsigned short expected_ss_size;
	bool genkey;
};

static const char zeroed_string[48];

static const struct cipher_testvec gost28147_tc26z_tv_template[] = {
	{
		.key	= "\x81\x82\x83\x84\x85\x86\x87\x88"
			  "\x89\x8a\x8b\x8c\x8d\x8e\x8f\x80"
			  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8"
			  "\xd9\xda\xdb\xdc\xdd\xde\xdf\xd0",
		.klen	= 32,
		.ptext	= "\x01\x02\x03\x04\x05\x06\x07\x08"
			  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8",
		.ctext	= "\xce\x5a\x5e\xd7\xe0\x57\x7a\x5f"
			  "\xd0\xcc\x85\xce\x31\x63\x5b\x8b",
		.len	= 16,
	} , {
		.key	= "\xcc\xdd\xee\xff\x88\x99\xaa\xbb"
			  "\x44\x55\x66\x77\x00\x11\x22\x33"
			  "\xf3\xf2\xf1\xf0\xf7\xf6\xf5\xf4"
			  "\xfb\xfa\xf9\xf8\xff\xfe\xfd\xfc",
		.klen	= 32,
		.ptext	= "\x10\x32\x54\x76\x98\xba\xdc\xfe",
		.ctext	= "\x3d\xca\xd8\xc2\xe5\x01\xe9\x4e",
		.len	= 8,
	},
};

static const struct hash_testvec gosthash94_tv_template[] = {
	{
		.plaintext = "",
		.psize = 0,
		.digest = "\x98\x1e\x5f\x3c\xa3\x0c\x84\x14"
			  "\x87\x83\x0f\x84\xfb\x43\x3e\x13"
			  "\xac\x11\x01\x56\x9b\x9c\x13\x58"
			  "\x4a\xc4\x83\x23\x4c\xd6\x56\xc0",
	}, {
		.plaintext = "a",
		.psize = 1,
		.digest = "\xe7\x4c\x52\xdd\x28\x21\x83\xbf"
			  "\x37\xaf\x00\x79\xc9\xf7\x80\x55"
			  "\x71\x5a\x10\x3f\x17\xe3\x13\x3c"
			  "\xef\xf1\xaa\xcf\x2f\x40\x30\x11",
	}, {
		.plaintext = "message digest",
		.psize = 14,
		.digest = "\xbc\x60\x41\xdd\x2a\xa4\x01\xeb"
			  "\xfa\x6e\x98\x86\x73\x41\x74\xfe"
			  "\xbd\xb4\x72\x9a\xa9\x72\xd6\x0f"
			  "\x54\x9a\xc3\x9b\x29\x72\x1b\xa0",
	}, {
		.plaintext = "The quick brown fox jumps over the lazy dog",
		.psize = 43,
		.digest = "\x90\x04\x29\x4a\x36\x1a\x50\x8c"
			  "\x58\x6f\xe5\x3d\x1f\x1b\x02\x74"
			  "\x67\x65\xe7\x1b\x76\x54\x72\x78"
			  "\x6e\x47\x70\xd5\x65\x83\x0a\x76",
	}
};

static struct cipher_testvec kuznyechik_tv_template[] = {
	{
		.key	= "\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
			  "\x00\x11\x22\x33\x44\x55\x66\x77"
			  "\xfe\xdc\xba\x98\x76\x54\x32\x10"
			  "\x01\x23\x45\x67\x89\xab\xcd\xef",
		.klen	= 32,
		.ptext	= "\x11\x22\x33\x44\x55\x66\x77\x00"
			  "\xff\xee\xdd\xcc\xbb\xaa\x99\x88"
			  "\x00\x11\x22\x33\x44\x55\x66\x77"
			  "\x88\x99\xaa\xbb\xcc\xee\xff\x0a"
			  "\x11\x22\x33\x44\x55\x66\x77\x88"
			  "\x99\xaa\xbb\xcc\xee\xff\x0a\x00"
			  "\x22\x33\x44\x55\x66\x77\x88\x99"
			  "\xaa\xbb\xcc\xee\xff\x0a\x00\x11",
		.ctext	= "\x7f\x67\x9d\x90\xbe\xbc\x24\x30"
			  "\x5a\x46\x8d\x42\xb9\xd4\xed\xcd"
			  "\xb4\x29\x91\x2c\x6e\x00\x32\xf9"
			  "\x28\x54\x52\xd7\x67\x18\xd0\x8b"
			  "\xf0\xca\x33\x54\x9d\x24\x7c\xee"
			  "\xf3\xf5\xa5\x31\x3b\xd4\xb1\x57"
			  "\xd0\xb0\x9c\xcd\xe8\x30\xb9\xeb"
			  "\x3a\x02\xc4\xc5\xaa\x8a\xda\x98",
	},
};

static struct cipher_testvec magma_tv_template[] = {
	{
		.key	= "\xff\xee\xdd\xcc\xbb\xaa\x99\x88"
			  "\x77\x66\x55\x44\x33\x22\x11\x00"
			  "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7"
			  "\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
		.klen	= 32,
		.ptext	= "\x92\xde\xf0\x6b\x3c\x13\x0a\x59"
			  "\xdb\x54\xc7\x04\xf8\x18\x9d\x20"
			  "\x4a\x98\xfb\x2e\x67\xa8\x02\x4c"
			  "\x89\x12\x40\x9b\x17\xb5\x7e\x41",
		.ctext	= "\x2b\x07\x3f\x04\x94\xf3\x72\xa0"
			  "\xde\x70\xe7\x15\xd3\x55\x6e\x48"
			  "\x11\xd8\xd9\xe9\xea\xcf\xbc\x1e"
			  "\x7c\x68\x26\x09\x96\xc6\x7e\xfb",
		.len	= 32,
	}, {
		.key	= "\xff\xee\xdd\xcc\xbb\xaa\x99\x88"
			  "\x77\x66\x55\x44\x33\x22\x11\x00"
			  "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7"
			  "\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
		.klen	= 32,
		.ptext	= "\xfe\xdc\xba\x98\x76\x54\x32\x10",
		.ctext	= "\x4e\xe9\x01\xe5\xc2\xd8\xca\x3d",
		.len	= 8,
	}, {
		.key	= "\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
			  "\x00\x11\x22\x33\x44\x55\x66\x77"
			  "\xfe\xdc\xba\x98\x76\x54\x32\x10"
			  "\x01\x23\x45\x67\x89\xab\xcd\xef",
		.klen	= 32,
		.ptext	= "\x12\x34\x56\x78\x00\x00\x00\x00",
		.ctext	= "\x3b\x9a\x2e\xaa\xbe\x78\x3b\xab",
		.len	= 8,
	}, {
		.key	= "\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
			  "\x00\x11\x22\x33\x44\x55\x66\x77"
			  "\xfe\xdc\xba\x98\x76\x54\x32\x10"
			  "\x01\x23\x45\x67\x89\xab\xcd\xef",
		.klen	= 32,
		.ptext	= "\x12\x34\x56\x78\x00\x00\x00\x01",
		.ctext	= "\x97\x0f\xd9\x08\x06\xc1\x0d\x62",
		.len	= 8,
	}, {
		.key	= "\x86\x3e\xa0\x17\x84\x2c\x3d\x37"
			  "\x2b\x18\xa8\x5a\x28\xe2\x31\x7d"
			  "\x74\xbe\xfc\x10\x77\x20\xde\x0c"
			  "\x9e\x8a\xb9\x74\xab\xd0\x0c\xa0",
		.klen	= 32,
		.ptext	= "\x12\x34\x56\x78\x00\x00\x00\x02",
		.ctext	= "\xc7\x3d\x45\x9c\x28\x7b\x3d\x1c",
		.len	= 8,
	}, {
		.key	= "\x86\x3e\xa0\x17\x84\x2c\x3d\x37"
			  "\x2b\x18\xa8\x5a\x28\xe2\x31\x7d"
			  "\x74\xbe\xfc\x10\x77\x20\xde\x0c"
			  "\x9e\x8a\xb9\x74\xab\xd0\x0c\xa0",
		.klen	= 32,
		.ptext	= "\x12\x34\x56\x78\x00\x00\x00\x03",
		.ctext	= "\x86\x36\x1c\xac\xbc\x1f\x4c\x24",
		.len	= 8,
	}, {
		.key	= "\x49\xa5\xe2\x67\x7d\xe5\x55\x98"
			  "\x2b\x8a\xd5\xe8\x26\x65\x2d\x17"
			  "\xee\xc8\x47\xbf\x5b\x39\x97\xa8"
			  "\x1c\xf7\xfe\x7f\x11\x87\xbd\x27",
		.klen	= 32,
		.ptext	= "\x12\x34\x56\x78\x00\x00\x00\x04",
		.ctext	= "\xb0\x8c\x42\x50\xcb\x8b\x64\x0a",
		.len	= 8,
	}, {
		.key	= "\x49\xa5\xe2\x67\x7d\xe5\x55\x98"
			  "\x2b\x8a\xd5\xe8\x26\x65\x2d\x17"
			  "\xee\xc8\x47\xbf\x5b\x39\x97\xa8"
			  "\x1c\xf7\xfe\x7f\x11\x87\xbd\x27",
		.klen	= 32,
		.ptext	= "\x12\x34\x56\x78\x00\x00\x00\x05",
		.ctext	= "\x32\x7e\xdc\xd4\xe8\x8d\xe6\x6f",
		.len	= 8,
	}, {
		.key	= "\x32\x56\xbf\x3f\x97\xb5\x66\x74"
			  "\x26\xa9\xfb\x1c\x5e\xaa\xbe\x41"
			  "\x89\x3c\xcd\xd5\xa8\x68\xf9\xb6"
			  "\x3b\x0a\xa9\x07\x20\xfa\x43\xc4",
		.klen	= 32,
		.ptext	= "\x12\x34\x56\x78\x00\x00\x00\x06",
		.ctext	= "\xa6\x91\xb5\x0e\x59\xbd\xfa\x58",
		.len	= 8,
	},
};

#endif	/* _CRYPTO_TESTMGR_H */
