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

static const struct cipher_testvec gost2814789_tc26z_tv_template[] = {
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

#endif	/* _CRYPTO_TESTMGR_H */
