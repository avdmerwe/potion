#ifndef POTION_TEST_H
#define POTION_TEST_H

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 */

#include <stdio.h>
#include <stdlib.h>

#define ARRAY_COUNT(x) (sizeof (x) / sizeof ((x)[0]))

static int test_failures = 0;
static int test_checks = 0;

#define CHECK(cond) do {						\
		test_checks++;							\
		if (!(cond))							\
		  {										\
			 test_failures++;					\
			 fprintf (stderr,"%s:%d: FAIL %s\n",	\
					  __FILE__,__LINE__,#cond);	\
		  }										\
	} while (0)

#define CHECK_EQ(a,b) do {									\
		long long _a = (long long) (a), _b = (long long) (b);	\
		test_checks++;										\
		if (_a != _b)										\
		  {													\
			 test_failures++;								\
			 fprintf (stderr,"%s:%d: FAIL %s == %s (%lld != %lld)\n",	\
					  __FILE__,__LINE__,#a,#b,_a,_b);		\
		  }													\
	} while (0)

static inline int test_result (const char *name)
{
   if (test_failures)
	 {
		fprintf (stderr,"%s: %d of %d checks FAILED\n",name,test_failures,test_checks);
		return (EXIT_FAILURE);
	 }

   printf ("%s: %d checks passed\n",name,test_checks);

   return (EXIT_SUCCESS);
}

#endif	/* #ifndef POTION_TEST_H */
