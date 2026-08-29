/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "link.h"

#define SLL_HDR_LEN		16			/* total header length				*/
#define SLL_PROTO_OFF	14			/* offset of the protocol field		*/

static int decode_sll (const void *buf,size_t caplen)
{
   const unsigned char *p = buf;
   uint16_t protocol;

   if (caplen < SLL_HDR_LEN)
	 return (-1);

   memcpy (&protocol,p + SLL_PROTO_OFF,sizeof (protocol));

   if (ntohs (protocol) != ETHERTYPE_IP)
	 return (-1);

   return (SLL_HDR_LEN);
}

struct link link_sll =
{
   .type	= DLT_LINUX_SLL,
   .decode	= decode_sll,
   .name	= "Linux cooked sockets"
};
