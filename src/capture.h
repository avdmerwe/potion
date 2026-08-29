#ifndef POTION_CAPTURE_H
#define POTION_CAPTURE_H

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 */

#include <stdint.h>

#include "config.h"

/*
 * Capture packets using the libpcap library. Returns
 * -1 if some error occurred, 0 if successful. The function
 * automatically logs error messages.
 */
extern int capture_open (const struct config *config);

/*
 * Stop capturing packets, remove event handlers, and free
 * all memory allocated by event handlers and capture_open().
 */
extern void capture_close (void);

/*
 * Returns non-zero if capture was terminated by an error rather
 * than by the user.
 */
extern int capture_failed (void);

/*
 * Number of packets that were dropped: those the kernel or libpcap
 * discarded because potion could not keep up, plus those potion could
 * not decode.
 */
extern uint64_t capture_dropped (void);

#endif	/* #ifndef POTION_CAPTURE_H */
