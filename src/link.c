/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 */

#include <stddef.h>

#include "link.h"

static struct link *link_list = NULL;

void link_register (struct link *link)
{
   link->next = NULL;

   if (link_list != NULL)
	 {
		struct link *tmp;

		for (tmp = link_list; tmp->next != NULL; tmp = tmp->next) ;
		tmp->next = link;
	 }
   else link_list = link;
}

const struct link *link_find (int type)
{
   const struct link *tmp;

   for (tmp = link_list; tmp != NULL; tmp = tmp->next)
	 if (tmp->type == type)
	   return (tmp);

   return (NULL);
}
