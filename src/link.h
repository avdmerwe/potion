#ifndef POTION_LINK_H
#define POTION_LINK_H

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 */

#include <sys/types.h>

struct link
{
   int type;
   /*
	* Return the number of bytes to skip to reach the IPv4 header, or -1
	* if the frame is truncated or does not carry IPv4.
	*/
   int (*decode) (const void *buf,size_t caplen);
   const char *name;
   struct link *next;
};

extern struct link link_ether;
extern struct link link_sll;

/*
 * Register a link layer module.
 */
extern void link_register (struct link *link);

/*
 * Return a pointer to a link layer module
 * structure.
 */
extern const struct link *link_find (int type);

#endif	/* #ifndef POTION_LINK_H */
