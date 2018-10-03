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

static int gost_test_init(void)
{
	int ret;
	int ok = true;

	ret = gost_alg_test("ecb(gost28147)", "ecb(gost28147)", 0, 0);
	if (ret < 0)
		ok = false;

	ret = gost_alg_test("ecb(magma)", "ecb(magma)", 0, 0);
	if (ret < 0)
		ok = false;

	ret = gost_alg_test("ecb(kuznyechik)", "ecb(kuznyechik)", 0, 0);
	if (ret < 0)
		ok = false;

	ret = gost_alg_test("gosthash94", "gosthash94", 0, 0);
	if (ret < 0)
		ok = false;

	ret = gost_alg_test("sb256", "sb256", 0, 0);
	if (ret < 0)
		ok = false;

	ret = gost_alg_test("sb512", "sb512", 0, 0);
	if (ret < 0)
		ok = false;

	return ok ? 0 : -1;
}
module_init(gost_test_init);

static void gost_test_exit(void)
{
}
module_exit(gost_test_exit);

MODULE_LICENSE("GPL v2");
