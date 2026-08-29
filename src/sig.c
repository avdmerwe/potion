/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 */

#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <event.h>

#include "gui.h"
#include "io.h"
#include "log.h"
#include "sig.h"
#include "util.h"

/* signals that must not disturb a full-screen session */
static const int sigset_ignore[] = { SIGUSR1, SIGUSR2, SIGTSTP, SIGPIPE };

/* signals that ask potion to shut down cleanly */
static const int sigset_accept[] = { SIGHUP, SIGINT, SIGTERM, SIGQUIT };

/*
 * Signals that mean the process is about to die. ncurses has put the
 * terminal in a state the shell cannot use, so it has to be reset before
 * the default action is allowed to run.
 */
static const int sigset_fatal[] = { SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT };

static struct event events[ARRAYSIZE (sigset_accept)];
static struct sigaction saved_ignore[ARRAYSIZE (sigset_ignore)];
static struct sigaction saved_fatal[ARRAYSIZE (sigset_fatal)];
static volatile sig_atomic_t installed = 0;

static void signal_event (int fd,short event,void *arg)
{
   size_t i;

   (void) event;
   (void) arg;

   log_printf (LOG_LEVEL_ERROR,"caught signal %d\n",fd);

   for (i = 0; i < ARRAYSIZE (sigset_accept); i++)
	 signal_del (events + i);

   gui_close ();
}

/*
 * Runs in true signal context, so it may only use async-signal-safe
 * calls. io_emergency_reset() replays the terminal teardown ncurses
 * would have done, using write(2) and tcsetattr(3) only, so the shell
 * that inherits the terminal still works.
 */
static void fatal_handler (int signum)
{
   struct sigaction sa;

   io_emergency_reset ();

   memset (&sa,0,sizeof (sa));
   sa.sa_handler = SIG_DFL;
   sigemptyset (&sa.sa_mask);
   sigaction (signum,&sa,NULL);

   raise (signum);
}

void sig_open (void)
{
   struct sigaction sa;
   size_t i;

   if (installed)
	 return;

   installed = 1;

   memset (&sa,0,sizeof (sa));
   sigemptyset (&sa.sa_mask);

   sa.sa_handler = SIG_IGN;

   for (i = 0; i < ARRAYSIZE (sigset_ignore); i++)
	 sigaction (sigset_ignore[i],&sa,saved_ignore + i);

   sa.sa_handler = fatal_handler;
   sa.sa_flags = SA_RESETHAND | SA_NODEFER;

   for (i = 0; i < ARRAYSIZE (sigset_fatal); i++)
	 sigaction (sigset_fatal[i],&sa,saved_fatal + i);

   for (i = 0; i < ARRAYSIZE (sigset_accept); i++)
	 {
		signal_set (events + i,sigset_accept[i],signal_event,NULL);
		signal_add (events + i,NULL);
	 }
}

void sig_close (void)
{
   size_t i;

   if (!installed)
	 return;

   installed = 0;

   for (i = 0; i < ARRAYSIZE (sigset_accept); i++)
	 signal_del (events + i);

   for (i = 0; i < ARRAYSIZE (sigset_fatal); i++)
	 sigaction (sigset_fatal[i],saved_fatal + i,NULL);

   for (i = 0; i < ARRAYSIZE (sigset_ignore); i++)
	 sigaction (sigset_ignore[i],saved_ignore + i,NULL);
}
