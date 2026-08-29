/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 *
 * Exercises flow aggregation, eviction and fragment reassembly.
 */

#include <string.h>
#include <time.h>
#include <event.h>

#include "../src/flow.h"
#include "test.h"

#define ACTIVE		3600
#define INACTIVE	600

static struct flow seen[64];
static size_t seen_count;

static void collect (const struct flow *flow)
{
   if (seen_count < ARRAY_COUNT (seen))
	 seen[seen_count++] = *flow;
}

static size_t snapshot (void)
{
   seen_count = 0;
   flow_process (collect);

   return (seen_count);
}

static struct flow make (uint32_t saddr,uint32_t daddr,uint16_t sport,uint16_t dport,
						 uint64_t octets,uint8_t flags,uint16_t id)
{
   struct flow flow;

   memset (&flow,0,sizeof (flow));

   flow.timestamp = time (NULL);
   flow.proto = IPPROTO_TCP;
   flow.saddr = saddr;
   flow.daddr = daddr;
   flow.sport = sport;
   flow.dport = dport;
   flow.octets = octets;
   flow.packets = 1;
   flow.flags = flags;
   flow.id = id;

   return (flow);
}

int main (void)
{
   struct flow flow;
   size_t i;

   event_init ();

   /* a zero sized table is refused rather than divided by */
   CHECK_EQ (flow_open (0,ACTIVE,INACTIVE),-1);

   /* and using the table anyway must not walk off an empty free list */
   flow = make (1,2,3,4,10,0,0);
   flow_insert (&flow);
   CHECK (flow_find (&flow) == NULL);
   CHECK_EQ (snapshot (),0);

   flow_close ();

   /* packets of the same flow are merged, not duplicated */
   CHECK_EQ (flow_open (8,ACTIVE,INACTIVE),0);

   flow = make (1,2,10,20,100,0,0);
   flow_insert (&flow);
   flow_insert (&flow);
   flow_insert (&flow);

   CHECK_EQ (snapshot (),1);
   CHECK_EQ (seen[0].octets,300);
   CHECK_EQ (seen[0].packets,3);

   /* the reverse direction is a different flow */
   flow = make (2,1,20,10,50,0,0);
   flow_insert (&flow);
   CHECK_EQ (snapshot (),2);

   flow_close ();

   /*
	* When the table is full the least recently updated flow is the one
	* that goes, so a busy table keeps rotating instead of pinning the
	* first four flows it ever saw.
	*/
   CHECK_EQ (flow_open (4,ACTIVE,INACTIVE),0);

   for (i = 0; i < 4; i++)
	 {
		flow = make ((uint32_t) (100 + i),200,(uint16_t) (i + 1),80,10,0,0);
		flow_insert (&flow);
	 }

   CHECK_EQ (snapshot (),4);

   /* touch the oldest so it is no longer the eviction candidate */
   flow = make (100,200,1,80,10,0,0);
   flow_insert (&flow);

   /* now add a fifth: flow 101 must go, 100 must survive */
   flow = make (104,200,5,80,10,0,0);
   flow_insert (&flow);

   CHECK_EQ (snapshot (),4);

   flow = make (100,200,1,80,0,0,0);
   CHECK (flow_find (&flow) != NULL);

   flow = make (101,200,2,80,0,0,0);
   CHECK (flow_find (&flow) == NULL);

   flow = make (104,200,5,80,0,0,0);
   CHECK (flow_find (&flow) != NULL);

   flow_close ();

   /* a later fragment arriving first is completed by the first fragment */
   CHECK_EQ (flow_open (8,ACTIVE,INACTIVE),0);

   flow = make (5,6,0,0,100,FLOW_FRAG | FLOW_PARTIAL,4242);
   flow_insert (&flow);
   CHECK_EQ (snapshot (),1);
   CHECK (seen[0].flags & FLOW_PARTIAL);

   flow = make (5,6,1111,2222,80,FLOW_FRAG,4242);
   flow_insert (&flow);

   CHECK_EQ (snapshot (),1);
   CHECK_EQ (seen[0].sport,1111);
   CHECK_EQ (seen[0].dport,2222);
   CHECK_EQ (seen[0].octets,180);
   CHECK_EQ (seen[0].packets,2);
   CHECK (seen[0].flags & FLOW_FRAG);
   CHECK (!(seen[0].flags & FLOW_PARTIAL));

   /* a further fragment merges into the completed flow */
   flow = make (5,6,0,0,20,FLOW_FRAG | FLOW_PARTIAL,4242);
   flow_insert (&flow);

   CHECK_EQ (snapshot (),1);
   CHECK_EQ (seen[0].octets,200);
   CHECK (!(seen[0].flags & FLOW_PARTIAL));

   flow_close ();

   /* the first fragment arriving first does not create a second flow */
   CHECK_EQ (flow_open (8,ACTIVE,INACTIVE),0);

   flow = make (7,8,53,53,100,FLOW_FRAG,99);
   flow_insert (&flow);

   flow = make (7,8,0,0,60,FLOW_FRAG | FLOW_PARTIAL,99);
   flow_insert (&flow);
   flow_insert (&flow);

   CHECK_EQ (snapshot (),1);
   CHECK_EQ (seen[0].octets,220);
   CHECK_EQ (seen[0].sport,53);

   /* an unrelated datagram reusing the same id is a separate flow */
   flow = make (7,8,0,0,10,FLOW_FRAG | FLOW_PARTIAL,1234);
   flow_insert (&flow);
   CHECK_EQ (snapshot (),2);

   flow_close ();

   /*
	* A second and third fragmented datagram on the same five-tuple must
	* fold into the same flow. Each first fragment merges into the
	* existing flow and has to carry its own datagram id in with it, or
	* its later fragments strand themselves in a partial flow that
	* nothing can complete.
	*/
   CHECK_EQ (flow_open (8,ACTIVE,INACTIVE),0);

   for (i = 0; i < 3; i++)
	 {
		uint16_t id = (uint16_t) (100 + i);

		flow = make (11,12,2049,5000,1500,FLOW_FRAG,id);
		flow_insert (&flow);

		flow = make (11,12,0,0,1500,FLOW_FRAG | FLOW_PARTIAL,id);
		flow_insert (&flow);

		flow = make (11,12,0,0,500,FLOW_FRAG | FLOW_PARTIAL,id);
		flow_insert (&flow);
	 }

   CHECK_EQ (snapshot (),1);
   CHECK_EQ (seen[0].octets,3 * 3500);
   CHECK_EQ (seen[0].packets,9);
   CHECK_EQ (seen[0].sport,2049);
   CHECK (!(seen[0].flags & FLOW_PARTIAL));

   flow_close ();

   /*
	* Fragments are matched on the datagram id, but only against flows
	* already known to be fragmented: ordinary traffic that happens to
	* reuse an id must not absorb them.
	*/
   CHECK_EQ (flow_open (8,ACTIVE,INACTIVE),0);

   flow = make (13,14,80,1024,100,0,777);		/* not a fragment */
   flow_insert (&flow);

   flow = make (13,14,0,0,50,FLOW_FRAG | FLOW_PARTIAL,777);
   flow_insert (&flow);

   CHECK_EQ (snapshot (),2);

   flow_close ();

   /*
	* The bitrate divides by the flow's age, so a flow created in the
	* current second, or one whose timestamp the clock stepped past, must
	* still produce a finite rate.
	*/
   CHECK_EQ (flow_open (8,ACTIVE,INACTIVE),0);

   flow = make (15,16,1,2,8000,0,0);
   flow.timestamp = time (NULL);				/* zero seconds old */
   flow_insert (&flow);

   flow = make (17,18,1,2,4000,0,0);
   flow.timestamp = time (NULL) + 3600;			/* clock stepped backwards */
   flow_insert (&flow);

   CHECK_EQ (snapshot (),2);

   for (i = 0; i < seen_count; i++)
	 {
		CHECK (seen[i].bitrate == seen[i].bitrate);			/* not NaN */
		CHECK (seen[i].bitrate < 1.0e18);					/* not infinite */
		CHECK (seen[i].bitrate > 0.0);
	 }

   flow_close ();

   /* flows are reported by bitrate, highest first */
   CHECK_EQ (flow_open (8,ACTIVE,INACTIVE),0);

   for (i = 0; i < 5; i++)
	 {
		flow = make ((uint32_t) (10 + i),20,(uint16_t) (i + 1),80,
					 (uint64_t) (i + 1) * 1000,0,0);
		flow.timestamp = time (NULL) - 10;
		flow_insert (&flow);
	 }

   CHECK_EQ (snapshot (),5);

   for (i = 0; i + 1 < seen_count; i++)
	 CHECK (seen[i].bitrate >= seen[i + 1].bitrate);

   CHECK_EQ (seen[0].octets,5000);

   /* an explicit removal frees the slot for reuse */
   flow = make (10,20,1,80,0,0,0);
   CHECK (flow_find (&flow) != NULL);
   flow_remove (flow_find (&flow));
   CHECK (flow_find (&flow) == NULL);
   CHECK_EQ (snapshot (),4);

   flow_close ();

   return (test_result ("test_flow"));
}
