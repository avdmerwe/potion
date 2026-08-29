#ifndef POTION_CONFIG_H
#define POTION_CONFIG_H

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 */

#include <sys/types.h>

struct config
{
   const char *progname;
   int snaplen;					/* bytes captured from each packet		*/
   size_t flows;				/* maximum number of tracked flows		*/
   time_t active;				/* active flow timeout, seconds			*/
   time_t inactive;				/* inactive flow timeout, seconds		*/
   int promisc;					/* put the interface in promiscuous mode	*/
   int facility;				/* syslog facility, from <syslog.h>		*/
   const char *iface;			/* interface to listen on (points into argv)	*/
   char *expr;					/* pcap filter expression, or NULL		*/
};

/*
 * Parse command-line parameters. Exits with a diagnostic on stderr if
 * the arguments are not valid.
 */
extern const struct config *config_parse (int argc,char *argv[]);

/*
 * Free memory allocated for configuration.
 */
extern void config_destroy (void);

#endif	/* #ifndef POTION_CONFIG_H */
