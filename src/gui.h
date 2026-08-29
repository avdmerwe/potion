#ifndef POTION_GUI_H
#define POTION_GUI_H

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 */

#include "config.h"

/*
 * Display flows using the ncurses library. Returns -1 if
 * some error occurred, 0 if successful. The function
 * automatically logs error messages.
 */
extern int gui_open (const struct config *config);

/*
 * Quit the GUI, free all memory, remove event handlers, etc.
 */
extern void gui_close (void);

#endif	/* #ifndef POTION_GUI_H */
