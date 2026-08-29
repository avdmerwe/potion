#ifndef POTION_FLOW_H
#define POTION_FLOW_H

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 */

#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <event.h>

#define FLOW_FIN		0x01	/* a FIN was seen						*/
#define FLOW_ACK		0x02	/* a FIN was seen and acknowledged		*/
#define FLOW_RST		0x04	/* the connection was reset				*/
#define FLOW_FRAG		0x08	/* the datagram was fragmented			*/
#define FLOW_PARTIAL	0x10	/* ports unknown; match on IP id instead	*/

struct flow
{
   time_t timestamp;			/* when flow was created			*/
   uint64_t octets,packets;		/* bytes, packets transferred		*/
   uint8_t proto;				/* protocol							*/
   uint8_t tos;					/* type of service					*/
   uint16_t id;					/* identification number			*/
   uint32_t saddr,daddr;		/* source, destination address		*/
   uint16_t sport,dport;		/* source, destination port			*/
   uint8_t flags;				/* some [tcp] flags					*/
   double bitrate;				/* average bitrate since creation	*/
   struct event active;
   struct event inactive;
   TAILQ_ENTRY (flow) link;		/* live list, or the free list	*/
};

/*
 * Allocate memory for storing flows. The number of stored flows
 * will be limited to the limit specified here. Returns 0 if
 * successful, -1 if we ran out of memory.
 */
extern int flow_open (size_t entries,time_t active,time_t inactive);

/*
 * Free resources allocated for flow repository.
 */
extern void flow_close (void);

/*
 * Insert a flow. If the flow is part of an existing flow, it will be
 * merged, else a new flow will be created.
 *
 * If there is no space left to store this flow, the least recently
 * updated flow is removed to make space for it.
 */
extern void flow_insert (const struct flow *flow);

/*
 * Remove a flow. The specified flow should be the
 * result of an earlier call to flow_find().
 */
extern void flow_remove (struct flow *flow);

/*
 * Find a flow.
 */
extern struct flow *flow_find (const struct flow *flow);

/*
 * Sort the flows by bitrate (descending order) and call
 * the specified function for each flow.
 */
extern void flow_process (void (*process) (const struct flow *));

#endif	/* #ifndef POTION_FLOW_H */
