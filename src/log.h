#ifndef POTION_LOG_H
#define POTION_LOG_H

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 *
 * Minimal logging shim. Messages go to stderr until the syslog backend
 * is selected, after which nothing is written to the terminal -- ncurses
 * owns it from that point on.
 */

#include <stdarg.h>

/*
 * Log levels, in decreasing order of severity. These deliberately do not
 * reuse the LOG_* names from <syslog.h>, which have different values.
 */
enum
{
   LOG_LEVEL_QUIET   = 0,
   LOG_LEVEL_ERROR   = 1,
   LOG_LEVEL_WARNING = 2,
   LOG_LEVEL_NORMAL  = 3
};

/*
 * Translate a syslog facility name ("daemon", "local0", ...) into its
 * <syslog.h> constant. Returns -1 if the name is not recognised.
 */
extern int log_facility (const char *name);

/*
 * Log messages of severity level or higher to stderr. This is the
 * initial state, so it only needs to be called to switch back.
 */
extern void log_open_stderr (int level);

/*
 * Log messages of severity level or higher to syslog. ident is copied.
 * Returns 0 if successful, -1 if memory could not be allocated.
 */
extern int log_open_syslog (const char *ident,int facility,int level);

/*
 * Release the resources held by the log system and revert to stderr.
 */
extern void log_close (void);

/*
 * printf()/vprintf() replacements. Every message is expected to end in a
 * newline; embedded newlines start a new syslog record.
 */
extern void log_printf (int level,const char *fmt, ...)
  __attribute__ ((format (printf,2,3)));
extern void log_vprintf (int level,const char *fmt,va_list ap);

#endif	/* #ifndef POTION_LOG_H */
