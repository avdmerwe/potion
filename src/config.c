/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "config.h"
#include "log.h"

/*
 * libpcap clamps anything larger than this, and anything smaller than a
 * link header plus a full IPv4 and TCP header cannot yield a usable flow.
 */
#define SNAPLEN_MIN		68
#define SNAPLEN_MAX		262144

#define FLOWS_MIN		16
#define FLOWS_MAX		1048576

#define ACTIVE_MIN		1		/* minutes */
#define ACTIVE_MAX		60

#define INACTIVE_MIN	10		/* seconds */
#define INACTIVE_MAX	600

static struct config config;

static void usage (FILE *stream,const char *progname)
{
   fprintf (stream,
			"usage: %s [options] <interface> [expression]\n"
			"\n"
			"   -s | --snaplen=<bytes>     capture bytes of data from each packet (%d-%d,\n"
			"                              or 0 for whole packets; default %d)\n"
			"   -f | --flows=<n>           maximum number of flows to track (%d-%d,\n"
			"                              default %d)\n"
			"   -a | --active=<minutes>    active flow timeout in minutes (%d-%d, default %d)\n"
			"   -i | --inactive=<seconds>  inactive flow timeout in seconds (%d-%d, default %d)\n"
			"   -S | --syslog=<facility>   syslog facility to log to (default user)\n"
			"   -P | --no-promisc          do not put the interface in promiscuous mode\n"
			"   -V | --version             show version information\n"
			"   -h | --help                show this help message\n"
			"\n",
			progname,
			SNAPLEN_MIN,SNAPLEN_MAX,128,
			FLOWS_MIN,FLOWS_MAX,64,
			ACTIVE_MIN,ACTIVE_MAX,30,
			INACTIVE_MIN,INACTIVE_MAX,30);
}

static __attribute__ ((noreturn,format (printf,1,2))) void fmterr (const char *fmt, ...)
{
   va_list ap;

   va_start (ap,fmt);
   vfprintf (stderr,fmt,ap);
   va_end (ap);

   config_destroy ();

   exit (EXIT_FAILURE);
}

static __attribute__ ((noreturn)) void nomem (void)
{
   fmterr ("%s: failed to allocate memory: %s\n",config.progname,strerror (errno));
}

/*
 * Parse an unsigned decimal number. Returns 0 if successful, -1 if str is
 * not a well-formed number or does not fit in a uint32_t.
 */
static int parse_u32 (const char *str,uint32_t *value)
{
   unsigned long result;
   char *end;

   if (str == NULL || *str < '0' || *str > '9')
	 return (-1);

   errno = 0;
   result = strtoul (str,&end,10);

   if (errno != 0 || *end != '\0' || result > UINT32_MAX)
	 return (-1);

   *value = (uint32_t) result;

   return (0);
}

/*
 * Join the remaining command-line arguments into a single
 * space-separated pcap filter expression.
 */
static char *copy_argv (int argc,char *argv[])
{
   size_t len = 0;
   char *str;
   int i;

   for (i = 0; i < argc; i++)
	 len += strlen (argv[i]) + 1;

   if ((str = malloc (len)) == NULL)
	 return (NULL);

   *str = '\0';

   for (i = 0; i < argc; i++)
	 {
		if (i)
		  strcat (str," ");

		strcat (str,argv[i]);
	 }

   return (str);
}

const struct config *config_parse (int argc,char *argv[])
{
   static const struct option option[] =
	 {
		{ "snaplen", 1, NULL, 's' },
		{ "flows", 1, NULL, 'f' },
		{ "active", 1, NULL, 'a' },
		{ "inactive", 1, NULL, 'i' },
		{ "syslog", 1, NULL, 'S' },
		{ "no-promisc", 0, NULL, 'P' },
		{ "version", 0, NULL, 'V' },
		{ "help", 0, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	 };
   int finished = 0;
   uint32_t value;

   opterr = 0;
   optind = 1;

   memset (&config,0,sizeof (struct config));

   config.progname = "potion";

   if (argc > 0 && argv[0] != NULL && *argv[0] != '\0')
	 {
		const char *slash = strrchr (argv[0],'/');
		config.progname = slash != NULL ? slash + 1 : argv[0];
	 }

   config.snaplen = 128;
   config.flows = 64;
   config.active = 30 * 60;
   config.inactive = 30;
   config.promisc = 1;
   config.facility = log_facility ("user");

   while (!finished)
	 {
		switch (getopt_long (argc,argv,"s:f:a:i:S:PVh",option,NULL))
		  {
		   case -1:
			 finished = 1;
			 break;

		   case 's':
			 if (parse_u32 (optarg,&value) ||
				 (value != 0 && (value < SNAPLEN_MIN || value > SNAPLEN_MAX)))
			   fmterr ("%s: snaplen must be 0 or %d-%d bytes\n",
					   config.progname,SNAPLEN_MIN,SNAPLEN_MAX);
			 config.snaplen = value != 0 ? (int) value : SNAPLEN_MAX;
			 break;

		   case 'f':
			 if (parse_u32 (optarg,&value) || value < FLOWS_MIN || value > FLOWS_MAX)
			   fmterr ("%s: maximum number of flows must be %d-%d entries\n",
					   config.progname,FLOWS_MIN,FLOWS_MAX);
			 config.flows = value;
			 break;

		   case 'a':
			 if (parse_u32 (optarg,&value) || value < ACTIVE_MIN || value > ACTIVE_MAX)
			   fmterr ("%s: active timeout must be %d-%d minutes\n",
					   config.progname,ACTIVE_MIN,ACTIVE_MAX);
			 config.active = (time_t) value * 60;
			 break;

		   case 'i':
			 if (parse_u32 (optarg,&value) || value < INACTIVE_MIN || value > INACTIVE_MAX)
			   fmterr ("%s: inactive timeout must be %d-%d seconds\n",
					   config.progname,INACTIVE_MIN,INACTIVE_MAX);
			 config.inactive = value;
			 break;

		   case 'S':
			 if ((config.facility = log_facility (optarg)) < 0)
			   fmterr ("%s: invalid syslog facility: %s\n",config.progname,optarg);
			 break;

		   case 'P':
			 config.promisc = 0;
			 break;

		   case 'V':
			 printf ("%s %s\n",config.progname,POTION_VERSION);
			 config_destroy ();
			 exit (EXIT_SUCCESS);

		   case 'h':
			 usage (stdout,config.progname);
			 config_destroy ();
			 exit (EXIT_SUCCESS);

		   default:
			 usage (stderr,config.progname);
			 fmterr ("%s: invalid option or missing argument\n",config.progname);
		  }
	 }

   if (optind >= argc)
	 {
		usage (stderr,config.progname);
		fmterr ("%s: no interface specified\n",config.progname);
	 }

   config.iface = argv[optind++];

   if (optind < argc && (config.expr = copy_argv (argc - optind,argv + optind)) == NULL)
	 nomem ();

   return (&config);
}

void config_destroy (void)
{
   free (config.expr);
   config.expr = NULL;
}
