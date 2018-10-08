/*
 * Copyright (c) 2018 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include "gost-test.h"

static const char *gost_tests[] = {
	"ecb(gost28147-tc26z)",
	"ecb(gost28147-cpa)",
	"ecb(gost28147-cpb)",
	"ecb(gost28147-cpc)",
	"ecb(gost28147-cpd)",
	"ecb(magma)",
	"ecb(kuznyechik)",
	"cmac(magma)",
	"cmac(kuznyechik)",
	"gost28147imit-tc26z",
	"gost28147imit-cpa",
	"gost28147imit-cpb",
	"gost28147imit-cpc",
	"gost28147imit-cpd",
	"gosthash94",
	"sb256",
	"sb512",
	"hmac(gosthash94)",
	"hmac(sb256)",
	"hmac(sb512)",
};

static int gost_test_init(void)
{
	int ret;
	unsigned int i;
	int ok = true;

	pr_info("Starting GOST crypto tests\n");
	for (i = 0; i < ARRAY_SIZE(gost_tests); i++) {
		ret = gost_alg_test(gost_tests[i], gost_tests[i], 0, 0);
		if (ret < 0)
			ok = false;
	}

	return ok ? 0 : -EIO;
}
module_init(gost_test_init);

static void gost_test_exit(void)
{
}
module_exit(gost_test_exit);

MODULE_LICENSE("GPL v2");
