/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 *
 * Feeds hand-built frames through the decoders and the IPv4 parser.
 *
 * capture.c is included rather than linked so the test can reach the
 * static parser directly. Every frame is handed to the parser in a heap
 * block sized exactly to the captured length, so a read past caplen is
 * a genuine heap overflow that ASan and valgrind will catch.
 */

#include <string.h>
#include <netinet/if_ether.h>

#include "../src/capture.c"
#include "test.h"

#define ETH_HLEN	14
#define ETHERTYPE_VLAN_TAG	0x8100
#define ETHERTYPE_QINQ_TAG	0x88a8
#define IP_HLEN		20
#define TCP_HLEN	20
#define UDP_HLEN	8

struct packet
{
   unsigned char *data;
   size_t len;
};

static struct packet packet_alloc (size_t len)
{
   struct packet p;

   p.data = malloc (len);
   p.len = len;

   if (p.data == NULL)
	 abort ();

   memset (p.data,0,len);

   return (p);
}

static void put16 (unsigned char *p,uint16_t v)
{
   p[0] = (unsigned char) (v >> 8);
   p[1] = (unsigned char) (v & 0xff);
}

static void put32 (unsigned char *p,uint32_t v)
{
   p[0] = (unsigned char) (v >> 24);
   p[1] = (unsigned char) ((v >> 16) & 0xff);
   p[2] = (unsigned char) ((v >> 8) & 0xff);
   p[3] = (unsigned char) (v & 0xff);
}

/* Ethernet header with the given ethertype */
static void put_ether (unsigned char *p,uint16_t type)
{
   put16 (p + 12,type);
}

/*
 * IPv4 header. ihl is written raw so the tests can supply illegal
 * values; tot_len, protocol and frag_off are likewise caller supplied.
 */
static void put_ip (unsigned char *p,unsigned ihl,uint16_t tot_len,uint8_t proto,
					uint16_t id,uint16_t frag_off,uint32_t saddr,uint32_t daddr)
{
   p[0] = (unsigned char) ((4 << 4) | (ihl & 0x0f));
   p[1] = 0;								/* tos */
   put16 (p + 2,tot_len);
   put16 (p + 4,id);
   put16 (p + 6,frag_off);
   p[8] = 64;								/* ttl */
   p[9] = proto;
   put16 (p + 10,0);						/* checksum */
   put32 (p + 12,saddr);
   put32 (p + 16,daddr);
}

static void put_ports (unsigned char *p,uint16_t sport,uint16_t dport)
{
   put16 (p,sport);
   put16 (p + 2,dport);
}

/* run one frame through the same path capture_process() uses */
static int decode (const struct link *link,struct packet pkt,uint32_t wirelen,struct flow *flow)
{
   int len = link->decode (pkt.data,pkt.len);

   memset (flow,0,sizeof (struct flow));

   if (len < 0)
	 return (-1);

   if ((uint32_t) len > pkt.len || (uint32_t) len > wirelen)
	 return (-1);

   return (packet_to_flowrec (flow,pkt.data + len,pkt.len - (size_t) len,
							  wirelen - (uint32_t) len));
}

static void free_packet (struct packet *p)
{
   free (p->data);
   p->data = NULL;
}

int main (void)
{
   struct flow flow;

   link_register (&link_ether);
   link_register (&link_sll);

   CHECK (link_find (DLT_EN10MB) == &link_ether);
   CHECK (link_find (DLT_LINUX_SLL) == &link_sll);
   CHECK (link_find (0x7fff) == NULL);

   /* a well formed TCP segment */
   {
	  struct packet p = packet_alloc (ETH_HLEN + IP_HLEN + TCP_HLEN);

	  put_ether (p.data,ETHERTYPE_IP);
	  put_ip (p.data + ETH_HLEN,5,IP_HLEN + TCP_HLEN,IPPROTO_TCP,0x1234,0,
			  0x0a000001,0x0a000002);
	  put_ports (p.data + ETH_HLEN + IP_HLEN,1234,80);

	  CHECK_EQ (decode (&link_ether,p,p.len,&flow),0);
	  CHECK_EQ (flow.proto,IPPROTO_TCP);
	  CHECK_EQ (flow.saddr,0x0a000001u);
	  CHECK_EQ (flow.daddr,0x0a000002u);
	  CHECK_EQ (flow.sport,1234);
	  CHECK_EQ (flow.dport,80);
	  CHECK_EQ (flow.id,0x1234);
	  CHECK_EQ (flow.flags,0);
	  /* accounted at the IP layer, not the frame */
	  CHECK_EQ (flow.octets,IP_HLEN + TCP_HLEN);

	  free_packet (&p);
   }

   /* Ethernet padding must not inflate the byte count */
   {
	  struct packet p = packet_alloc (60);

	  put_ether (p.data,ETHERTYPE_IP);
	  put_ip (p.data + ETH_HLEN,5,IP_HLEN + UDP_HLEN,IPPROTO_UDP,1,0,1,2);
	  put_ports (p.data + ETH_HLEN + IP_HLEN,53,53);

	  CHECK_EQ (decode (&link_ether,p,60,&flow),0);
	  CHECK_EQ (flow.octets,IP_HLEN + UDP_HLEN);

	  free_packet (&p);
   }

   /* a truncated capture must be rejected, not read past the end */
   {
	  size_t caplen;

	  for (caplen = 0; caplen < ETH_HLEN + IP_HLEN; caplen++)
		{
		   struct packet p = packet_alloc (caplen);

		   if (caplen >= ETH_HLEN)
			 {
				put_ether (p.data,ETHERTYPE_IP);

				if (caplen >= ETH_HLEN + 1)
				  p.data[ETH_HLEN] = (4 << 4) | 5;
			 }

		   /* the frame was longer on the wire; only caplen bytes exist */
		   CHECK_EQ (decode (&link_ether,p,1500,&flow),-1);

		   free_packet (&p);
		}
   }

   /* an IP header length below the fixed 20 bytes is malformed */
   {
	  unsigned ihl;

	  for (ihl = 0; ihl < 5; ihl++)
		{
		   struct packet p = packet_alloc (ETH_HLEN + IP_HLEN + TCP_HLEN);

		   put_ether (p.data,ETHERTYPE_IP);
		   put_ip (p.data + ETH_HLEN,ihl,IP_HLEN + TCP_HLEN,IPPROTO_TCP,1,0,1,2);

		   CHECK_EQ (decode (&link_ether,p,p.len,&flow),-1);

		   free_packet (&p);
		}
   }

   /* a header longer than the captured data is rejected */
   {
	  struct packet p = packet_alloc (ETH_HLEN + IP_HLEN + TCP_HLEN);

	  put_ether (p.data,ETHERTYPE_IP);
	  put_ip (p.data + ETH_HLEN,15,IP_HLEN + TCP_HLEN,IPPROTO_TCP,1,0,1,2);

	  CHECK_EQ (decode (&link_ether,p,p.len,&flow),-1);

	  free_packet (&p);
   }

   /* IP options are skipped so the ports are still found */
   {
	  struct packet p = packet_alloc (ETH_HLEN + 24 + TCP_HLEN);

	  put_ether (p.data,ETHERTYPE_IP);
	  put_ip (p.data + ETH_HLEN,6,24 + TCP_HLEN,IPPROTO_TCP,1,0,1,2);
	  put_ports (p.data + ETH_HLEN + 24,4321,443);

	  CHECK_EQ (decode (&link_ether,p,p.len,&flow),0);
	  CHECK_EQ (flow.sport,4321);
	  CHECK_EQ (flow.dport,443);

	  free_packet (&p);
   }

   /* a truncated transport header yields no ports and no read past the end */
   {
	  struct packet p = packet_alloc (ETH_HLEN + IP_HLEN + TCP_HLEN - 1);

	  put_ether (p.data,ETHERTYPE_IP);
	  put_ip (p.data + ETH_HLEN,5,IP_HLEN + TCP_HLEN,IPPROTO_TCP,1,0,1,2);

	  CHECK_EQ (decode (&link_ether,p,ETH_HLEN + IP_HLEN + TCP_HLEN,&flow),-1);

	  free_packet (&p);
   }

   /* a version other than 4 is not IPv4 */
   {
	  struct packet p = packet_alloc (ETH_HLEN + IP_HLEN + TCP_HLEN);

	  put_ether (p.data,ETHERTYPE_IP);
	  put_ip (p.data + ETH_HLEN,5,IP_HLEN,IPPROTO_TCP,1,0,1,2);
	  p.data[ETH_HLEN] = (6 << 4) | 5;

	  CHECK_EQ (decode (&link_ether,p,p.len,&flow),-1);

	  free_packet (&p);
   }

   /* a lying tot_len falls back to the wire length */
   {
	  struct packet p = packet_alloc (ETH_HLEN + IP_HLEN + UDP_HLEN);

	  put_ether (p.data,ETHERTYPE_IP);
	  put_ip (p.data + ETH_HLEN,5,60000,IPPROTO_UDP,1,0,1,2);

	  CHECK_EQ (decode (&link_ether,p,p.len,&flow),0);
	  CHECK_EQ (flow.octets,IP_HLEN + UDP_HLEN);

	  free_packet (&p);
   }

   /* a first fragment keeps its ports and is not marked partial */
   {
	  struct packet p = packet_alloc (ETH_HLEN + IP_HLEN + UDP_HLEN);

	  put_ether (p.data,ETHERTYPE_IP);
	  put_ip (p.data + ETH_HLEN,5,IP_HLEN + UDP_HLEN,IPPROTO_UDP,7,0x2000,1,2);
	  put_ports (p.data + ETH_HLEN + IP_HLEN,1000,2000);

	  CHECK_EQ (decode (&link_ether,p,p.len,&flow),0);
	  CHECK (flow.flags & FLOW_FRAG);
	  CHECK (!(flow.flags & FLOW_PARTIAL));
	  CHECK_EQ (flow.sport,1000);

	  free_packet (&p);
   }

   /* a later fragment has no ports and is marked partial */
   {
	  struct packet p = packet_alloc (ETH_HLEN + IP_HLEN + 8);

	  put_ether (p.data,ETHERTYPE_IP);
	  put_ip (p.data + ETH_HLEN,5,IP_HLEN + 8,IPPROTO_UDP,7,0x00b9,1,2);

	  CHECK_EQ (decode (&link_ether,p,p.len,&flow),0);
	  CHECK (flow.flags & FLOW_FRAG);
	  CHECK (flow.flags & FLOW_PARTIAL);
	  CHECK_EQ (flow.sport,0);
	  CHECK_EQ (flow.dport,0);

	  free_packet (&p);
   }

   /* TCP teardown flags */
   {
	  struct packet p = packet_alloc (ETH_HLEN + IP_HLEN + TCP_HLEN);

	  put_ether (p.data,ETHERTYPE_IP);
	  put_ip (p.data + ETH_HLEN,5,IP_HLEN + TCP_HLEN,IPPROTO_TCP,1,0,1,2);
	  put_ports (p.data + ETH_HLEN + IP_HLEN,1,2);
	  p.data[ETH_HLEN + IP_HLEN + 12] = 5 << 4;		/* data offset */
	  p.data[ETH_HLEN + IP_HLEN + 13] = 0x11;		/* FIN | ACK */

	  CHECK_EQ (decode (&link_ether,p,p.len,&flow),0);
	  CHECK (flow.flags & FLOW_FIN);
	  CHECK (flow.flags & FLOW_ACK);

	  p.data[ETH_HLEN + IP_HLEN + 13] = 0x04;		/* RST */
	  CHECK_EQ (decode (&link_ether,p,p.len,&flow),0);
	  CHECK (flow.flags & FLOW_RST);

	  free_packet (&p);
   }

   /* non-IPv4 ethertypes are dropped by the link decoder */
   {
	  struct packet p = packet_alloc (ETH_HLEN + IP_HLEN + TCP_HLEN);

	  put_ether (p.data,0x86dd);					/* IPv6 */
	  CHECK_EQ (link_ether.decode (p.data,p.len),-1);

	  put_ether (p.data,0x0806);					/* ARP */
	  CHECK_EQ (link_ether.decode (p.data,p.len),-1);

	  free_packet (&p);
   }

   /* single and double VLAN tags are peeled off */
   {
	  struct packet p = packet_alloc (ETH_HLEN + 4 + IP_HLEN + TCP_HLEN);

	  put_ether (p.data,ETHERTYPE_VLAN_TAG);
	  put16 (p.data + ETH_HLEN,100);				/* tci */
	  put16 (p.data + ETH_HLEN + 2,ETHERTYPE_IP);
	  put_ip (p.data + ETH_HLEN + 4,5,IP_HLEN + TCP_HLEN,IPPROTO_TCP,1,0,9,8);
	  put_ports (p.data + ETH_HLEN + 4 + IP_HLEN,7,9);

	  CHECK_EQ (link_ether.decode (p.data,p.len),ETH_HLEN + 4);
	  CHECK_EQ (decode (&link_ether,p,p.len,&flow),0);
	  CHECK_EQ (flow.saddr,9u);
	  CHECK_EQ (flow.sport,7);

	  free_packet (&p);
   }

   {
	  struct packet p = packet_alloc (ETH_HLEN + 8 + IP_HLEN + TCP_HLEN);

	  put_ether (p.data,ETHERTYPE_QINQ_TAG);
	  put16 (p.data + ETH_HLEN,100);
	  put16 (p.data + ETH_HLEN + 2,ETHERTYPE_VLAN_TAG);
	  put16 (p.data + ETH_HLEN + 4,200);
	  put16 (p.data + ETH_HLEN + 6,ETHERTYPE_IP);
	  put_ip (p.data + ETH_HLEN + 8,5,IP_HLEN + TCP_HLEN,IPPROTO_TCP,1,0,3,4);

	  CHECK_EQ (link_ether.decode (p.data,p.len),ETH_HLEN + 8);

	  free_packet (&p);
   }

   /* a VLAN tag with nothing after it must not be walked past */
   {
	  struct packet p = packet_alloc (ETH_HLEN + 2);

	  put_ether (p.data,ETHERTYPE_VLAN_TAG);
	  CHECK_EQ (link_ether.decode (p.data,p.len),-1);

	  free_packet (&p);
   }

   /* Linux cooked capture */
   {
	  struct packet p = packet_alloc (16 + IP_HLEN + UDP_HLEN);

	  put16 (p.data + 14,ETHERTYPE_IP);
	  put_ip (p.data + 16,5,IP_HLEN + UDP_HLEN,IPPROTO_UDP,1,0,0x0a0b0c0d,0x01020304);
	  put_ports (p.data + 16 + IP_HLEN,111,222);

	  CHECK_EQ (link_sll.decode (p.data,p.len),16);
	  CHECK_EQ (decode (&link_sll,p,p.len,&flow),0);
	  CHECK_EQ (flow.saddr,0x0a0b0c0du);
	  CHECK_EQ (flow.dport,222);

	  free_packet (&p);
   }

   {
	  struct packet p = packet_alloc (15);

	  CHECK_EQ (link_sll.decode (p.data,p.len),-1);

	  free_packet (&p);
   }

   return (test_result ("test_capture"));
}
