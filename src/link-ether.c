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

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN	0x8100		/* IEEE 802.1Q VLAN tag			*/
#endif

#ifndef ETHERTYPE_QINQ
#define ETHERTYPE_QINQ	0x88a8		/* IEEE 802.1ad service VLAN tag	*/
#endif

#define VLAN_TAG_LEN	4			/* TPID and TCI follow the ethertype	*/
#define VLAN_MAX_TAGS	2			/* accept at most a QinQ double tag		*/

static int decode_ether (const void *buf,size_t caplen)
{
   const unsigned char *p = buf;
   size_t offset = ETHER_HDR_LEN;
   uint16_t type;
   int i;

   if (caplen < ETHER_HDR_LEN)
	 return (-1);

   memcpy (&type,p + ETHER_ADDR_LEN * 2,sizeof (type));
   type = ntohs (type);

   /* peel off any 802.1Q/802.1ad tags stacked in front of the payload */
   for (i = 0; i < VLAN_MAX_TAGS && (type == ETHERTYPE_VLAN || type == ETHERTYPE_QINQ); i++)
	 {
		if (caplen < offset + VLAN_TAG_LEN)
		  return (-1);

		memcpy (&type,p + offset + 2,sizeof (type));
		type = ntohs (type);
		offset += VLAN_TAG_LEN;
	 }

   if (type != ETHERTYPE_IP)
	 return (-1);

   return ((int) offset);
}

struct link link_ether =
{
   .type	= DLT_EN10MB,
   .decode	= decode_ether,
   .name	= "Ethernet Encapsulation (RFC 894)"
};
