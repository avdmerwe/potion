#ifndef POTION_IO_H
#define POTION_IO_H

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 *
 * Thin wrapper around the handful of ncurses calls potion needs.
 */

#include <wchar.h>

/*
 * Colors
 */

#define ATTR_COLOR_BLACK	0
#define ATTR_COLOR_RED		1
#define ATTR_COLOR_GREEN	2
#define ATTR_COLOR_YELLOW	3
#define ATTR_COLOR_BLUE		4
#define ATTR_COLOR_MAGENTA	5
#define ATTR_COLOR_CYAN		6
#define ATTR_COLOR_WHITE	7

/*
 * Attributes
 */

#define ATTR_OFF			0			/* All attributes off			*/
#define ATTR_BOLD			1			/* Bold on						*/
#define ATTR_DIM			2			/* Dim							*/
#define ATTR_UNDERLINE		3			/* Underline					*/
#define ATTR_BLINK			4			/* Blink on						*/
#define ATTR_REVERSE		5			/* Reverse video on				*/

/*
 * Keys
 */

#define KEY_CTRL(x)			((x) & 0x1f)

struct line
{
   wchar_t tl;		/* Top Left         */
   wchar_t tr;		/* Top Right        */
   wchar_t bl;		/* Bottom Left      */
   wchar_t br;		/* Bottom Right     */
   wchar_t lt;		/* Left T           */
   wchar_t rt;		/* Right T          */
   wchar_t tt;		/* Top T            */
   wchar_t bt;		/* Bottom T         */
   wchar_t ct;		/* Center T         */
   wchar_t hl;		/* Horizontal Line  */
   wchar_t vl;		/* Vertical Line    */
};

/* line drawing characters */
extern struct line line;

/*
 * Init & Close
 */

/* Initialize screen. Returns 0 if successful, -1 otherwise. */
extern int io_open (void);

/* Restore original screen state */
extern void io_close (void);

/*
 * Hand the terminal back from a signal handler, using only
 * async-signal-safe calls. Does nothing if io_open() never succeeded.
 */
extern void io_emergency_reset (void);

/*
 * Output
 */

/* Set color attributes */
extern void out_setattr (int attr);

/* Set color */
extern void out_setcolor (int fg,int bg);

/* Move cursor to position (x,y) on the screen. Upper corner of screen is (0,0) */
extern void out_gotoxy (int x,int y);

/* Put a character on the screen */
extern void out_putc (wchar_t c);

/* Put a string on the screen */
extern void out_puts (const char *s);

/* Write a string to the screen */
extern void out_printf (const char *format, ...)
  __attribute__ ((format (printf,1,2)));

/* Write updates to screen */
extern void out_flush (void);

/* Completely redraw screen on next flush */
extern void out_refresh (void);

/* Get the screen width */
extern int out_width (void);

/* Get the screen height */
extern int out_height (void);

/* Beep */
extern void out_beep (void);

/* Clear screen */
extern void out_clear (void);

/*
 * Input
 */

/* Read a character without blocking. Returns -1 if nothing is pending. */
extern int in_getc (void);

/* Returns non-zero if c is the terminal resize pseudo-key */
extern int in_isresize (int c);

#endif	/* #ifndef POTION_IO_H */
