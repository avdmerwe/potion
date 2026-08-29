/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <event.h>

#include "flow.h"
#include "log.h"

TAILQ_HEAD (flow_list,flow);

struct flow_data
{
   struct flow *pool;		/* single allocation holding every entry	*/
   struct flow **sorted;	/* scratch array used to order the display	*/
   size_t entries;			/* size of both allocations					*/
   struct flow_list live;	/* flows in use, least recently used first	*/
   struct flow_list idle;	/* free list								*/
   time_t active;			/* active timeout							*/
   time_t inactive;			/* inactive timeout							*/
};

static struct flow_data flow_data;

int flow_open (size_t entries,time_t active,time_t inactive)
{
   size_t i;

   memset (&flow_data,0,sizeof (struct flow_data));
   TAILQ_INIT (&flow_data.live);
   TAILQ_INIT (&flow_data.idle);
   flow_data.active = active;
   flow_data.inactive = inactive;

   if (entries == 0 || entries > SIZE_MAX / sizeof (struct flow *))
	 return (-1);

   if ((flow_data.pool = calloc (entries,sizeof (struct flow))) == NULL)
	 return (-1);

   if ((flow_data.sorted = calloc (entries,sizeof (struct flow *))) == NULL)
	 {
		free (flow_data.pool);
		flow_data.pool = NULL;
		return (-1);
	 }

   flow_data.entries = entries;

   for (i = 0; i < entries; i++)
	 TAILQ_INSERT_TAIL (&flow_data.idle,&flow_data.pool[i],link);

   return (0);
}

void flow_close (void)
{
   struct flow *flow,*next;

   for (flow = TAILQ_FIRST (&flow_data.live); flow != NULL; flow = next)
	 {
		next = TAILQ_NEXT (flow,link);

		evtimer_del (&flow->active);
		evtimer_del (&flow->inactive);
	 }

   TAILQ_INIT (&flow_data.live);
   TAILQ_INIT (&flow_data.idle);

   free (flow_data.pool);
   free (flow_data.sorted);

   flow_data.pool = NULL;
   flow_data.sorted = NULL;
   flow_data.entries = 0;
}

static void flow_timeout (int fd,short event,void *arg)
{
   (void) fd;
   (void) event;

   flow_remove (arg);
}

/*
 * Arm the inactivity timer and move the flow to the tail of the live
 * list, so the head is always the flow that has gone longest without an
 * update and is therefore the one to recycle when the table is full.
 */
static void flow_touch (struct flow *flow)
{
   struct timeval tv = { .tv_sec = flow_data.inactive, .tv_usec = 0 };

   evtimer_del (&flow->inactive);

   if (evtimer_add (&flow->inactive,&tv))
	 log_printf (LOG_LEVEL_WARNING,"failed to arm inactivity timer\n");

   TAILQ_REMOVE (&flow_data.live,flow,link);
   TAILQ_INSERT_TAIL (&flow_data.live,flow,link);
}

static struct flow *flow_find_fragment (const struct flow *flow);

void flow_insert (const struct flow *flow)
{
   struct timeval tv;
   struct flow tmp = *flow;
   struct flow *entry;

   /*
	* Only the first fragment of a datagram carries the port numbers, and
	* the fragments may arrive in any order. Fragments seen before the
	* first one are accumulated in a flow matched on the IP id; when the
	* first fragment finally shows up it absorbs that flow and the result
	* is matched like any other flow from then on.
	*/

   if ((tmp.flags & FLOW_FRAG) && !(tmp.flags & FLOW_PARTIAL) &&
	   (entry = flow_find_fragment (&tmp)) != NULL && (entry->flags & FLOW_PARTIAL))
	 {
		tmp.octets += entry->octets;
		tmp.packets += entry->packets;
		tmp.flags |= entry->flags & ~FLOW_PARTIAL;

		if (entry->timestamp < tmp.timestamp)
		  tmp.timestamp = entry->timestamp;

		flow_remove (entry);
	 }

   if ((entry = flow_find (&tmp)) != NULL)
	 {
		entry->octets += tmp.octets;
		entry->packets += tmp.packets;

		/*
		 * FLOW_PARTIAL is a property of the entry, not of the packet: a
		 * later fragment must never push a flow whose ports are already
		 * known back into the match-on-id state.
		 */
		entry->flags |= tmp.flags & ~FLOW_PARTIAL;

		/*
		 * Later fragments can only be matched on the datagram id, so a
		 * first fragment merging into an existing flow has to bring its
		 * id with it. Without this the flow keeps the id of whichever
		 * datagram created it and every subsequent fragmented datagram
		 * on the same five-tuple strands its own later fragments in a
		 * partial flow nothing can ever complete.
		 *
		 * One id per flow still cannot follow two fragmented datagrams
		 * interleaved on one five-tuple; the second one's fragments are
		 * accounted separately until they time out.
		 */

		if ((tmp.flags & FLOW_FRAG) && !(tmp.flags & FLOW_PARTIAL))
		  entry->id = tmp.id;

		flow_touch (entry);

		return;
	 }

   if ((entry = TAILQ_FIRST (&flow_data.idle)) != NULL)
	 TAILQ_REMOVE (&flow_data.idle,entry,link);
   else if ((entry = TAILQ_FIRST (&flow_data.live)) != NULL)
	 {
		/* the table is full: recycle the least recently updated flow */
		evtimer_del (&entry->active);
		evtimer_del (&entry->inactive);
		TAILQ_REMOVE (&flow_data.live,entry,link);
	 }
   else return;			/* the flow table was never opened */

   *entry = tmp;

   TAILQ_INSERT_TAIL (&flow_data.live,entry,link);

   /* set active timer (fires when the flow grows too old) */
   tv.tv_sec = flow_data.active, tv.tv_usec = 0;
   evtimer_set (&entry->active,flow_timeout,entry);

   if (evtimer_add (&entry->active,&tv))
	 log_printf (LOG_LEVEL_WARNING,"failed to arm flow timer\n");

   /* set inactive timer (fires when the flow stops being updated) */
   tv.tv_sec = flow_data.inactive, tv.tv_usec = 0;
   evtimer_set (&entry->inactive,flow_timeout,entry);

   if (evtimer_add (&entry->inactive,&tv))
	 log_printf (LOG_LEVEL_WARNING,"failed to arm inactivity timer\n");
}

void flow_remove (struct flow *flow)
{
   evtimer_del (&flow->active);
   evtimer_del (&flow->inactive);
   TAILQ_REMOVE (&flow_data.live,flow,link);
   TAILQ_INSERT_HEAD (&flow_data.idle,flow,link);
}

static struct flow *flow_find_normal (const struct flow *flow)
{
   struct flow *entry;

   TAILQ_FOREACH (entry,&flow_data.live,link)
	 if (entry != flow &&
		 !(entry->flags & FLOW_PARTIAL) &&
		 entry->proto == flow->proto &&
		 entry->tos == flow->tos &&
		 entry->saddr == flow->saddr &&
		 entry->daddr == flow->daddr &&
		 entry->sport == flow->sport &&
		 entry->dport == flow->dport)
	   return (entry);

   return (NULL);
}

/*
 * Fragments carry no port numbers, so they can only be matched on the
 * datagram identification. Restricting the search to flows already known
 * to be fragmented keeps unrelated traffic that happens to reuse an IP id
 * from being folded in.
 */
static struct flow *flow_find_fragment (const struct flow *flow)
{
   struct flow *entry;

   TAILQ_FOREACH (entry,&flow_data.live,link)
	 if (entry != flow &&
		 (entry->flags & FLOW_FRAG) &&
		 entry->proto == flow->proto &&
		 entry->tos == flow->tos &&
		 entry->saddr == flow->saddr &&
		 entry->daddr == flow->daddr &&
		 entry->id == flow->id)
	   return (entry);

   return (NULL);
}

struct flow *flow_find (const struct flow *flow)
{
   return (!(flow->flags & FLOW_PARTIAL) ?
		   flow_find_normal (flow) :
		   flow_find_fragment (flow));
}

/*
 * Order by bitrate, highest first. The remaining fields break ties so
 * that flows sharing a rate -- every flow that has not moved any traffic
 * yet, for one -- keep a stable position between refreshes instead of
 * shuffling on every redraw.
 */
static int flow_compare (const void *a,const void *b)
{
   const struct flow *x = *(const struct flow *const *) a;
   const struct flow *y = *(const struct flow *const *) b;

   if (x->bitrate != y->bitrate)
	 return (x->bitrate > y->bitrate ? -1 : 1);

   if (x->saddr != y->saddr)
	 return (x->saddr < y->saddr ? -1 : 1);

   if (x->daddr != y->daddr)
	 return (x->daddr < y->daddr ? -1 : 1);

   if (x->sport != y->sport)
	 return (x->sport < y->sport ? -1 : 1);

   if (x->dport != y->dport)
	 return (x->dport < y->dport ? -1 : 1);

   if (x->proto != y->proto)
	 return (x->proto < y->proto ? -1 : 1);

   if (x->tos != y->tos)
	 return (x->tos < y->tos ? -1 : 1);

   if (x->id != y->id)
	 return (x->id < y->id ? -1 : 1);

   return (0);
}

void flow_process (void (*process) (const struct flow *))
{
   time_t now = time (NULL);
   struct flow *flow;
   size_t count = 0,i;

   TAILQ_FOREACH (flow,&flow_data.live,link)
	 {
		time_t elapsed = now - flow->timestamp;

		/*
		 * A flow created in the current second, or one whose timestamp
		 * is in the future because the clock stepped backwards, is
		 * charged a single second so the division stays finite.
		 */
		flow->bitrate = (double) flow->octets / (double) (elapsed > 0 ? elapsed : 1);

		if (count < flow_data.entries)
		  flow_data.sorted[count++] = flow;
	 }

   if (count == 0)
	 return;

   qsort (flow_data.sorted,count,sizeof (struct flow *),flow_compare);

   for (i = 0; i < count; i++)
	 process (flow_data.sorted[i]);
}
