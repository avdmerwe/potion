/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 */

/* IP_MF, IP_OFFMASK and the non-BSD struct tcphdr/udphdr member names */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <event.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "capture.h"
#include "config.h"
#include "flow.h"
#include "link.h"
#include "log.h"

/*
 * Packets handled per trip through the event loop. Passing -1 to
 * pcap_dispatch() lets a busy interface starve the user interface, the
 * flow timers and signal delivery for as long as traffic keeps arriving.
 */
#define CAPTURE_BUDGET	1024

/*
 * Ethernet pads a frame's payload out to this many bytes, so at or below
 * it the wire length tells us nothing about the real datagram size.
 */
#define ETHER_MIN_PAYLOAD	46

struct capture
{
   const struct link *link;
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t *pcap;
   struct event event;
   uint64_t runts;			/* packets too short or malformed to decode	*/
   int failed;
};

static struct capture capture;

/*
 * Decode an IPv4 datagram into a flow record. buf/len describe the bytes
 * libpcap actually captured; wirelen is the length the datagram had on
 * the wire, which may be larger. Returns 0 if successful, -1 if the
 * packet was too short or malformed.
 */
static int packet_to_flowrec (struct flow *flow,const unsigned char *buf,size_t len,uint32_t wirelen)
{
   struct iphdr ip;
   uint16_t frag_off,tot_len;
   size_t hlen;

   /*
	* The capture buffer has no alignment guarantees once the link-layer
	* header has been skipped, so headers are copied out rather than
	* accessed through a cast pointer.
	*/

   if (len < sizeof (struct iphdr))
	 {
		capture.runts++;
		return (-1);
	 }

   memcpy (&ip,buf,sizeof (struct iphdr));

   if (ip.version != 4)
	 {
		capture.runts++;
		return (-1);
	 }

   hlen = (size_t) ip.ihl << 2;

   /* a header shorter than the fixed part is malformed, not merely short */
   if (hlen < sizeof (struct iphdr) || len < hlen)
	 {
		capture.runts++;
		return (-1);
	 }

   buf += hlen;
   len -= hlen;

   flow->proto = ip.protocol;
   flow->saddr = ntohl (ip.saddr);
   flow->daddr = ntohl (ip.daddr);
   flow->tos = ip.tos;
   flow->id = ntohs (ip.id);

   /*
	* Account the IP datagram rather than the frame. The two differ only
	* for short packets, where Ethernet pads the payload out to
	* ETHER_MIN_PAYLOAD and the wire length overstates the datagram.
	*
	* Which of the two to believe is a trade-off, because tot_len is
	* attacker controlled: above the padding threshold the wire length is
	* authoritative and preferring it stops a sender understating its own
	* traffic by an order of magnitude, and at or below it the wire
	* length says nothing, so the advertised length is all there is.
	*/

   tot_len = ntohs (ip.tot_len);

   flow->octets = wirelen <= ETHER_MIN_PAYLOAD && tot_len >= hlen && tot_len <= wirelen ?
	 tot_len : wirelen;

   /*
	* Trailing bytes after the end of the datagram -- Ethernet padding,
	* or anything a sender chooses to append -- are not part of it and
	* must not be parsed as a transport header.
	*/

   if (tot_len >= hlen && (size_t) (tot_len - hlen) < len)
	 len = (size_t) (tot_len - hlen);

   /*
	* Since we don't know the order in which we will receive
	* fragments and only the first fragment contains the header
	* information we first create a flow without all the upper
	* layer info.
	*
	* When the time comes and we receive the first fragment, we
	* fill in the blanks and aggregate the flow.
	*
	* If either the fragment flow or the real flow expires before
	* this process is complete (or during a fragment flow), two
	* different flows will be exported. There is not much we can
	* do about that situation though.
	*
	* All the juicy bits of how fragments are matched and flows
	* aggregated can be found in flow.c
	*/

   frag_off = ntohs (ip.frag_off);

   if (frag_off & (IP_OFFMASK | IP_MF))
	 {
		flow->flags |= FLOW_FRAG;

		if (frag_off & IP_OFFMASK)
		  {
			 flow->flags |= FLOW_PARTIAL;
			 return (0);
		  }
	 }

   switch (flow->proto)
	 {
	  case IPPROTO_UDP:
		  {
			 struct udphdr udp;

			 if (len < sizeof (struct udphdr))
			   {
				  capture.runts++;
				  return (-1);
			   }

			 memcpy (&udp,buf,sizeof (struct udphdr));

			 flow->sport = ntohs (udp.source);
			 flow->dport = ntohs (udp.dest);
		  }
		break;

	  case IPPROTO_TCP:
		  {
			 struct tcphdr tcp;

			 if (len < sizeof (struct tcphdr))
			   {
				  capture.runts++;
				  return (-1);
			   }

			 memcpy (&tcp,buf,sizeof (struct tcphdr));

			 flow->sport = ntohs (tcp.source);
			 flow->dport = ntohs (tcp.dest);

			 if (tcp.fin)
			   flow->flags |= FLOW_FIN;

			 /*
			  * We're only interested in ACKs after we received
			  * a FIN. If this is the side who closed the connection,
			  * the FIN would've been saved earlier on, else we
			  * would've gotten the FIN now.
			  */

			 if ((flow->flags & FLOW_FIN) && tcp.ack)
			   flow->flags |= FLOW_ACK;

			 if (tcp.rst)
			   flow->flags |= FLOW_RST;
		  }
		break;
	 }

   return (0);
}

static void capture_process (u_char *user,const struct pcap_pkthdr *h,const u_char *sp)
{
   const unsigned char *buf = sp;
   struct flow flow;
   uint32_t wirelen;
   size_t caplen;
   int len;

   (void) user;

   if ((len = capture.link->decode (buf,h->caplen)) < 0)
	 return;

   /* the decoder validated caplen, so neither subtraction can wrap */
   if ((uint32_t) len > h->caplen || (uint32_t) len > h->len)
	 {
		capture.runts++;
		return;
	 }

   buf += len;
   caplen = h->caplen - (uint32_t) len;
   wirelen = h->len - (uint32_t) len;

   memset (&flow,0,sizeof (struct flow));

   flow.timestamp = h->ts.tv_sec;
   flow.packets = 1;

   if (packet_to_flowrec (&flow,buf,caplen,wirelen))
	 return;

   if ((flow.flags & (FLOW_FIN | FLOW_ACK)) == (FLOW_FIN | FLOW_ACK) ||
	   (flow.flags & FLOW_RST))
	 {
		struct flow *tmp;

		if ((tmp = flow_find (&flow)) != NULL)
		  flow_remove (tmp);

		return;
	 }

   flow_insert (&flow);
}

static void capture_dispatch (int fd,short event,void *arg)
{
   (void) fd;
   (void) event;
   (void) arg;

   if (pcap_dispatch (capture.pcap,CAPTURE_BUDGET,capture_process,NULL) < 0)
	 {
		log_printf (LOG_LEVEL_ERROR,"capture failed: %s\n",pcap_geterr (capture.pcap));
		capture.failed = 1;
		capture_close ();
		event_loopexit (NULL);
	 }
}

int capture_open (const struct config *config)
{
   int type;

   if ((capture.pcap = pcap_open_live (config->iface,
									   config->snaplen,
									   config->promisc,
									   1000,
									   capture.errbuf)) == NULL)
	 {
		log_printf (LOG_LEVEL_ERROR,"%s\n",capture.errbuf);
		return (-1);
	 }

   if (pcap_setnonblock (capture.pcap,1,capture.errbuf))
	 {
		log_printf (LOG_LEVEL_ERROR,"%s\n",capture.errbuf);
		pcap_close (capture.pcap);
		return (-1);
	 }

   type = pcap_datalink (capture.pcap);

   if ((capture.link = link_find (type)) == NULL)
	 {
		log_printf (LOG_LEVEL_ERROR,"unsupported link layer: %s\n",
					pcap_datalink_val_to_name (type) != NULL ?
					pcap_datalink_val_to_name (type) : "unknown");
		pcap_close (capture.pcap);
		return (-1);
	 }

   if (config->expr != NULL)
	 {
		bpf_u_int32 net,mask;
		struct bpf_program bpf;

		if (pcap_lookupnet (config->iface,&net,&mask,capture.errbuf))
		  {
			 log_printf (LOG_LEVEL_WARNING,"%s\n",capture.errbuf);
			 net = mask = 0;
		  }

		if (pcap_compile (capture.pcap,&bpf,config->expr,1,mask))
		  {
			 log_printf (LOG_LEVEL_ERROR,"%s\n",pcap_geterr (capture.pcap));
			 pcap_close (capture.pcap);
			 return (-1);
		  }

		if (pcap_setfilter (capture.pcap,&bpf))
		  {
			 log_printf (LOG_LEVEL_ERROR,"%s\n",pcap_geterr (capture.pcap));
			 pcap_freecode (&bpf);
			 pcap_close (capture.pcap);
			 return (-1);
		  }

		pcap_freecode (&bpf);
	 }

   if (flow_open (config->flows,config->active,config->inactive))
	 {
		log_printf (LOG_LEVEL_ERROR,"failed to allocate memory for %zu flows\n",config->flows);
		pcap_close (capture.pcap);
		return (-1);
	 }

   event_set (&capture.event,
			  pcap_fileno (capture.pcap),
			  EV_READ | EV_PERSIST,
			  capture_dispatch,NULL);

   if (event_add (&capture.event,NULL))
	 {
		log_printf (LOG_LEVEL_ERROR,"failed to add capture event handler\n");
		flow_close ();
		pcap_close (capture.pcap);
		return (-1);
	 }

   return (0);
}

void capture_close (void)
{
   static volatile sig_atomic_t called = 0;

   if (!called)
	 {
		called = 1;
		event_del (&capture.event);
		flow_close ();
		pcap_close (capture.pcap);
		capture.pcap = NULL;
	 }
}

int capture_failed (void)
{
   return (capture.failed);
}

uint64_t capture_dropped (void)
{
   struct pcap_stat stats;

   /*
	* Packets the kernel or libpcap discarded because potion could not
	* keep up, plus the ones potion itself could not make sense of.
	*/

   if (capture.pcap != NULL && pcap_stats (capture.pcap,&stats) == 0)
	 return (capture.runts + stats.ps_drop + stats.ps_ifdrop);

   return (capture.runts);
}
