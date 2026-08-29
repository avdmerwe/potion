/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 */

/* setgroups() */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <event.h>

#include "capture.h"
#include "config.h"
#include "gui.h"
#include "link.h"
#include "log.h"

/*
 * Read an id out of the environment. Returns 0 and stores the value if
 * the variable is present and holds a plain decimal number that fits,
 * -1 otherwise. Zero is rejected: it is root, which is never a target
 * to drop to.
 */
static int getenv_id (const char *name,unsigned long limit,unsigned long *value)
{
   const char *str = getenv (name);
   unsigned long result;
   char *end;

   if (str == NULL || *str < '0' || *str > '9')
	 return (-1);

   errno = 0;
   result = strtoul (str,&end,10);

   if (errno != 0 || *end != '\0' || result == 0 || result > limit)
	 return (-1);

   *value = result;

   return (0);
}

/*
 * Capturing needs privileges, watching the results does not. Once the
 * capture handle is open and the filter is compiled, nothing potion does
 * requires them any more, so give them back.
 *
 * There is only something to give back when potion was started through
 * sudo or from a set-user-ID binary; a genuine root login keeps its
 * privileges because there is no unprivileged identity to return to.
 *
 * Returns 0 if the process ended up unprivileged or was never
 * privileged, -1 if a drop was attempted and could not be completed. A
 * partial drop is always reported as a failure: continuing with some
 * privileges retained would defeat the point.
 */
static int drop_privileges (void)
{
   uid_t uid = getuid ();
   gid_t gid = getgid ();
   unsigned long value;

   if (geteuid () != 0)
	 return (0);

   if (uid == 0)
	 {
		/* started through sudo: go back to the invoking user */
		if (getenv_id ("SUDO_UID",(unsigned long) (uid_t) -1,&value))
		  return (0);

		uid = (uid_t) value;

		/*
		 * SUDO_GID is only usable when it is present, well formed and
		 * not root; otherwise the user's own primary group is the right
		 * answer. Leaving gid at the caller's 0 would keep the process
		 * in the root group, which is most of what we came to give up.
		 */

		if (getenv_id ("SUDO_GID",(unsigned long) (gid_t) -1,&value) == 0)
		  gid = (gid_t) value;
		else
		  {
			 const struct passwd *pw = getpwuid (uid);

			 if (pw == NULL || pw->pw_gid == 0)
			   {
				  log_printf (LOG_LEVEL_ERROR,
							  "cannot determine a group to drop to for uid %lu\n",
							  (unsigned long) uid);
				  return (-1);
			   }

			 gid = pw->pw_gid;
		  }
	 }

   if (uid == 0 || gid == 0)
	 return (0);

   if (setgroups (1,&gid) || setgid (gid) || setuid (uid))
	 {
		log_printf (LOG_LEVEL_ERROR,"failed to drop privileges: %s\n",strerror (errno));
		return (-1);
	 }

   /* a drop that can be undone, or that left an id behind, is not a drop */
   if (getuid () != uid || geteuid () != uid ||
	   getgid () != gid || getegid () != gid ||
	   setuid (0) != -1 || setgid (0) != -1)
	 {
		log_printf (LOG_LEVEL_ERROR,"failed to drop privileges permanently\n");
		return (-1);
	 }

   return (0);
}

int main (int argc,char *argv[])
{
   const struct config *config;

   log_open_stderr (LOG_LEVEL_NORMAL);
   atexit (log_close);

   config = config_parse (argc,argv);
   atexit (config_destroy);

   if (!isatty (STDIN_FILENO) || !isatty (STDOUT_FILENO))
	 {
		log_printf (LOG_LEVEL_ERROR,"standard input and output must be a terminal\n");
		exit (EXIT_FAILURE);
	 }

   link_register (&link_ether);
   link_register (&link_sll);

   event_init ();

   /*
	* Open the capture handle and give the privileges back before doing
	* anything else, so the rest of the session -- the terminal included
	* -- runs unprivileged. Both steps still report to stderr, where the
	* user can see them; gui_open() switches the log to syslog once
	* ncurses owns the terminal.
	*/

   if (capture_open (config))
	 exit (EXIT_FAILURE);

   atexit (capture_close);

   if (drop_privileges ())
	 exit (EXIT_FAILURE);

   if (gui_open (config))
	 exit (EXIT_FAILURE);

   atexit (gui_close);

   /*
	* event_dispatch() returns 0 when the loop was asked to exit and 1
	* when it ran out of registered events, which is how a clean quit
	* looks. Only a negative return is an error.
	*/
   if (event_dispatch () < 0)
	 {
		log_printf (LOG_LEVEL_ERROR,"event loop failed: %s\n",strerror (errno));
		exit (EXIT_FAILURE);
	 }

   exit (capture_failed () ? EXIT_FAILURE : EXIT_SUCCESS);
}
