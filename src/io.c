/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 */

#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <ncurses.h>
#include <term.h>

#include "io.h"

/* Number of colors defined in io.h */
#define NUM_COLORS	8

/* Number of attributes defined in io.h */
#define NUM_ATTRS	6

/* Cursor definitions */
#define CURSOR_INVISIBLE	0
#define CURSOR_NORMAL		1

/* Maps color definitions onto their real definitions */
static const int color_map[NUM_COLORS] =
{
   [ATTR_COLOR_BLACK]	= COLOR_BLACK,
   [ATTR_COLOR_RED]		= COLOR_RED,
   [ATTR_COLOR_GREEN]	= COLOR_GREEN,
   [ATTR_COLOR_YELLOW]	= COLOR_YELLOW,
   [ATTR_COLOR_BLUE]	= COLOR_BLUE,
   [ATTR_COLOR_MAGENTA]	= COLOR_MAGENTA,
   [ATTR_COLOR_CYAN]	= COLOR_CYAN,
   [ATTR_COLOR_WHITE]	= COLOR_WHITE
};

/* Maps attribute definitions onto their real definitions */
static const attr_t attr_map[NUM_ATTRS] =
{
   [ATTR_OFF]		= A_NORMAL,
   [ATTR_BOLD]		= A_BOLD,
   [ATTR_DIM]		= A_DIM,
   [ATTR_UNDERLINE]	= A_UNDERLINE,
   [ATTR_BLINK]		= A_BLINK,
   [ATTR_REVERSE]	= A_REVERSE
};

/* Current attribute used on screen */
static attr_t out_attr = A_NORMAL;

/* Set once the screen has been initialised */
static int initialized = 0;

/* The screen, so it can be torn down again */
static SCREEN *screen = NULL;

/*
 * Everything needed to hand the terminal back, captured before ncurses
 * takes it over so that it can be replayed from a signal handler using
 * nothing but write(2) and tcsetattr(3), both async-signal-safe.
 */
static char reset_seq[256];
static size_t reset_len = 0;
static struct termios reset_termios;
static int have_termios = 0;

static void reset_append (const char *capability)
{
   const char *seq = tigetstr ((NCURSES_CONST char *) capability);
   size_t len;

   if (seq == NULL || seq == (const char *) -1)
	 return;

   len = strlen (seq);

   if (reset_len + len >= sizeof (reset_seq))
	 return;

   memcpy (reset_seq + reset_len,seq,len);
   reset_len += len;
}

/* Set if the terminal can actually do colour */
static int have_colors = 0;

struct line line;

/*
 * Init & Close
 */

int io_open (void)
{
   if (initialized)
	 return (0);

   /* capture the line discipline before ncurses changes it */
   have_termios = tcgetattr (STDIN_FILENO,&reset_termios) == 0;

   /*
	* newterm() rather than initscr(): initscr() prints to stderr and
	* calls exit() when the terminal cannot be set up, which gives the
	* caller no chance to unwind.
	*/
   if ((screen = newterm (NULL,stdout,stdin)) == NULL)
	 {
		have_termios = 0;
		return (-1);
	 }

   initialized = 1;

   /*
	* Turning attributes off, putting the keypad back in local mode,
	* showing the cursor and leaving the alternate screen is what
	* endwin() would do; capturing it now means a fatal signal can do it
	* too, without calling anything unsafe.
	*/
   reset_len = 0;
   reset_append ("sgr0");
   reset_append ("rmkx");
   reset_append ("cnorm");
   reset_append ("rmcup");

   if (reset_len == 0)
	 {
		/* no terminfo entry for any of them; ANSI is the best guess left */
		static const char ansi[] = "\033[0m\033[?1l\033>\033[?25h\033[?1049l";

		memcpy (reset_seq,ansi,sizeof (ansi) - 1);
		reset_len = sizeof (ansi) - 1;
	 }

   if ((have_colors = has_colors ()) != 0)
	 start_color ();

   curs_set (CURSOR_INVISIBLE);
   out_attr = A_NORMAL;
   noecho ();
   cbreak ();
   keypad (stdscr,TRUE);

   /*
	* The screen is driven from the event loop, so a read must never
	* block: in_getc() reports "nothing pending" instead.
	*/
   nodelay (stdscr,TRUE);

   line = (struct line) {
	  .tl = ACS_ULCORNER,
	  .tr = ACS_URCORNER,
	  .bl = ACS_LLCORNER,
	  .br = ACS_LRCORNER,
	  .lt = ACS_LTEE,
	  .rt = ACS_RTEE,
	  .tt = ACS_TTEE,
	  .bt = ACS_BTEE,
	  .ct = ACS_PLUS,
	  .hl = ACS_HLINE,
	  .vl = ACS_VLINE,
   };

   return (0);
}

void io_close (void)
{
   if (!initialized)
	 return;

   initialized = 0;

   attrset (A_NORMAL);
   erase ();
   echo ();
   curs_set (CURSOR_NORMAL);
   refresh ();
   endwin ();

   if (screen != NULL)
	 {
		delscreen (screen);
		screen = NULL;
	 }

   reset_len = 0;
   have_termios = 0;
}

/*
 * Hand the terminal back from a signal handler. Only write(2) and
 * tcsetattr(3) are used, both of which POSIX requires to be
 * async-signal-safe; nothing in ncurses is. Does nothing if the screen
 * was never taken over.
 */
void io_emergency_reset (void)
{
   if (reset_len != 0)
	 {
		ssize_t written = write (STDOUT_FILENO,reset_seq,reset_len);

		(void) written;
	 }

   if (have_termios)
	 (void) tcsetattr (STDIN_FILENO,TCSANOW,&reset_termios);
}

/*
 * Output
 */

void out_setattr (int attr)
{
   out_attr = attr >= 0 && attr < NUM_ATTRS ? attr_map[attr] : A_NORMAL;
}

void out_setcolor (int fg,int bg)
{
   short pair;

   if (fg < 0 || fg >= NUM_COLORS || bg < 0 || bg >= NUM_COLORS)
	 return;

   if (!have_colors)
	 {
		attrset (out_attr);
		return;
	 }

   /* colour pair 0 is reserved by ncurses for the default colours */
   pair = (short) (((bg << 3) | fg) + 1);

   if (pair < COLOR_PAIRS)
	 {
		init_pair (pair,(short) color_map[fg],(short) color_map[bg]);
		attrset (COLOR_PAIR (pair) | out_attr);
	 }
   else attrset (out_attr);
}

void out_gotoxy (int x,int y)
{
   move (y,x);
}

void out_putc (wchar_t c)
{
   addch ((chtype) c);
}

void out_puts (const char *s)
{
   addstr (s);
}

void out_printf (const char *format, ...)
{
   va_list ap;

   va_start (ap,format);
   vw_printw (stdscr,format,ap);
   va_end (ap);
}

void out_flush (void)
{
   refresh ();
}

void out_refresh (void)
{
   clearok (stdscr,TRUE);
}

int out_width (void)
{
   return (COLS);
}

int out_height (void)
{
   return (LINES);
}

void out_beep (void)
{
   beep ();
}

void out_clear (void)
{
   erase ();
   move (0,0);
}

/*
 * Input
 */

int in_getc (void)
{
   int c = getch ();

   return (c == ERR ? -1 : c);
}

int in_isresize (int c)
{
   return (c == KEY_RESIZE);
}
