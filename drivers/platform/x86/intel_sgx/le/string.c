// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>

#include <linux/types.h>

void *memset(void *s, int c, size_t n)
{
	unsigned long i;

	for (i = 0; i < n; i++)
		((unsigned char *)s)[i] = c;

	return s;
}

void *memcpy(void *dest, const void *src, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		((char *)dest)[i] = ((char *)src)[i];

	return dest;
}
