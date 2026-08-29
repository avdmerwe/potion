#ifndef POTION_UTIL_H
#define POTION_UTIL_H

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 */

#include <stdint.h>

#define ARRAYSIZE(x) (sizeof (x) / sizeof ((x)[0]))

/*
 * Expand a host-order IPv4 address into four printf arguments,
 * most significant octet first.
 */
#define HIPQUAD(addr)					\
	(unsigned) (((uint32_t) (addr) >> 24) & 0xff),	\
	(unsigned) (((uint32_t) (addr) >> 16) & 0xff),	\
	(unsigned) (((uint32_t) (addr) >>  8) & 0xff),	\
	(unsigned) ( (uint32_t) (addr)        & 0xff)

#endif	/* #ifndef POTION_UTIL_H */
