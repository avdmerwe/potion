/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 *
 * Minimal logging shim, replacing the logging half of libdebug 0.4.3.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "log.h"
#include "util.h"

/*
 * The facility names potion accepts. glibc can supply this table via
 * SYSLOG_NAMES, but that macro *defines* facilitynames[] in every
 * translation unit that uses it, so we carry our own.
 */
static const struct
{
   const char *name;
   int value;
} facility[] =
{
   { "authpriv", LOG_AUTHPRIV },
   { "cron",     LOG_CRON     },
   { "daemon",   LOG_DAEMON   },
   { "ftp",      LOG_FTP      },
   { "kern",     LOG_KERN     },
   { "lpr",      LOG_LPR      },
   { "mail",     LOG_MAIL     },
   { "news",     LOG_NEWS     },
   { "syslog",   LOG_SYSLOG   },
   { "user",     LOG_USER     },
   { "uucp",     LOG_UUCP     },
   { "local0",   LOG_LOCAL0   },
   { "local1",   LOG_LOCAL1   },
   { "local2",   LOG_LOCAL2   },
   { "local3",   LOG_LOCAL3   },
   { "local4",   LOG_LOCAL4   },
   { "local5",   LOG_LOCAL5   },
   { "local6",   LOG_LOCAL6   },
   { "local7",   LOG_LOCAL7   }
};

/* syslog priority for each of our levels */
static const int priority[] =
{
   [LOG_LEVEL_QUIET]   = LOG_NOTICE,
   [LOG_LEVEL_ERROR]   = LOG_ERR,
   [LOG_LEVEL_WARNING] = LOG_WARNING,
   [LOG_LEVEL_NORMAL]  = LOG_NOTICE
};

static int log_level = LOG_LEVEL_NORMAL;
static int log_syslog = 0;
static char *log_ident = NULL;

int log_facility (const char *name)
{
   size_t i;

   if (name == NULL)
	 return (-1);

   for (i = 0; i < ARRAYSIZE (facility); i++)
	 if (!strcmp (name,facility[i].name))
	   return (facility[i].value);

   return (-1);
}

void log_open_stderr (int level)
{
   log_close ();
   log_level = level;
}

int log_open_syslog (const char *ident,int facility_value,int level)
{
   char *copy;

   /* openlog() keeps the pointer, it does not copy the string */
   if ((copy = strdup (ident != NULL ? ident : "potion")) == NULL)
	 return (-1);

   log_close ();

   log_ident = copy;
   log_level = level;
   log_syslog = 1;

   openlog (log_ident,LOG_PID,facility_value);

   return (0);
}

void log_close (void)
{
   if (log_syslog)
	 {
		closelog ();
		log_syslog = 0;
	 }

   free (log_ident);
   log_ident = NULL;
}

void log_vprintf (int level,const char *fmt,va_list ap)
{
   char buf[2048];
   int n;

   if (level == LOG_LEVEL_QUIET || log_level == LOG_LEVEL_QUIET || level > log_level)
	 return;

   n = vsnprintf (buf,sizeof (buf),fmt,ap);

   if (n < 0)
	 return;

   if (!log_syslog)
	 {
		fputs (buf,stderr);
		fflush (stderr);
		return;
	 }

   /* one syslog record per line, without the trailing newline */
   for (char *s = buf, *nl; *s != '\0'; s = nl)
	 {
		if ((nl = strchr (s,'\n')) != NULL)
		  *nl++ = '\0';
		else
		  nl = s + strlen (s);

		if (*s != '\0')
		  syslog (priority[level < 0 || level > LOG_LEVEL_NORMAL ? LOG_LEVEL_NORMAL : level],"%s",s);
	 }
}

void log_printf (int level,const char *fmt, ...)
{
   va_list ap;

   va_start (ap,fmt);
   log_vprintf (level,fmt,ap);
   va_end (ap);
}
