#ifndef POTION_SIG_H
#define POTION_SIG_H

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 */

/*
 * Install signal handler events. The event library must be
 * initialized prior to calling this function.
 */
extern void sig_open (void);

/*
 * Uninstall signal handlers and restore the dispositions that were in
 * effect beforehand.
 */
extern void sig_close (void);

#endif	/* #ifndef POTION_SIG_H */
