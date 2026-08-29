/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2004-2026 Abraham van der Merwe <abz@frogfoot.com>
 */

#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <event.h>
#include <netinet/in.h>

#include "capture.h"
#include "flow.h"
#include "gui.h"
#include "io.h"
#include "log.h"
#include "sig.h"
#include "util.h"

#define PUTC_AT(c,x,y) do {			\
		out_gotoxy (x,y); out_putc (c);	\
	} while (0)

#define PUTS_AT(s,x,y) do {			\
		out_gotoxy (x,y); out_puts (s);	\
	} while (0)

/*
 * Below this the columns are narrower than the widest value they can
 * hold -- "255.255.255.255:65535" is 21 characters -- and addresses
 * would start dropping out of rows instead of being displayed.
 */
#define MIN_WIDTH	72
#define MIN_HEIGHT	10

/*
 * Keys consumed per trip through the event loop. Bounded for the same
 * reason the capture is: a held key or a large paste must not starve the
 * redraw or the timers.
 */
#define KEY_BUDGET	64

/*
 * A readable terminal that yields no key this many times running has
 * gone away. Without a limit the event fires forever and potion spins.
 */
#define EMPTY_READ_LIMIT	64

struct gui
{
   struct event event;
   struct event timer;
   void (*display) (void);
   int width,height,y;
   int column[3];
   size_t flows;
   int empty_reads;
};

static struct gui gui;

static void hline (int x1,int x2,int y)
{
   int x;

   out_gotoxy (x1,y);

   for (x = x1; x <= x2; x++)
	 out_putc (line.hl);
}

static void vline (int x,int y1,int y2)
{
   int y;

   for (y = y1; y <= y2; y++)
	 {
		out_gotoxy (x,y);
		out_putc (line.vl);
	 }
}

static void drawrate (int x,int y,int w,double rate)
{
   static const char *const suffix[] = { "", "k", "m", "g", "t" };
   char buf[32];
   size_t n = 0;
   int len;

   if (w < 4)
	 return;

   rate *= 8.0;

   if (!isfinite (rate) || rate < 0.0)
	 rate = 0.0;

   while (n + 1 < ARRAYSIZE (suffix) && rate >= 1000.0)
	 {
		rate /= 1000.0;
		n++;
	 }

   len = snprintf (buf,sizeof (buf),"%.1f%s",rate,suffix[n]);

   if (len < 0 || (size_t) len >= sizeof (buf) || (size_t) len > (size_t) w)
	 strcpy (buf,"ovf");

   out_setattr (ATTR_BOLD);
   out_setcolor (ATTR_COLOR_GREEN,ATTR_COLOR_BLACK);
   out_gotoxy (x,y);
   out_printf ("%*s",w,buf);
}

static void drawaddr (int x,int y,int w,uint32_t addr,uint16_t port)
{
   char buf[32];
   int len;

   if (w <= 0)
	 return;

   len = snprintf (buf,sizeof (buf),"%u.%u.%u.%u",HIPQUAD (addr));

   if (len > 0 && (size_t) len < sizeof (buf) && port)
	 len += snprintf (buf + len,sizeof (buf) - (size_t) len,":%u",(unsigned) port);

   if (len < 0 || (size_t) len > (size_t) w)
	 return;

   out_setattr (ATTR_OFF);
   out_setcolor (ATTR_COLOR_CYAN,ATTR_COLOR_BLACK);
   out_gotoxy (x,y);
   out_puts (buf);
}

static void drawproto (int x,int y,int w,uint8_t proto,int isfrag)
{
   static const struct
	 {
		uint8_t value;
		const char *name;
	 } list[] =
	 {
		{ IPPROTO_TCP, "tcp" },			/* Transmission Control Protocol		*/
		{ IPPROTO_UDP, "udp" },			/* User Datagram Protocol				*/
		{ IPPROTO_ICMP, "icmp" },		/* Internet Control Message Protocol	*/
		{ IPPROTO_IPIP, "ipip" },		/* IPIP tunnels							*/
		{ IPPROTO_GRE, "gre" },			/* General Routing Encapsulation		*/
		{ IPPROTO_ESP, "esp" },			/* Encapsulating Security Payload		*/
		{ IPPROTO_AH, "ah" },			/* Authentication Header				*/
		{ IPPROTO_SCTP, "sctp" },		/* Stream Control Transmission Protocol	*/
		{ IPPROTO_IPV6, "6in4" }		/* IPv6 tunnelled over IPv4				*/
	 };
   char buf[32];
   size_t i,len;

   if (w <= 0)
	 return;

   for (i = 0; i < ARRAYSIZE (list); i++)
	 if (proto == list[i].value)
	   break;

   len = (size_t) snprintf (buf,sizeof (buf),"%s%s",
							i < ARRAYSIZE (list) ? list[i].name : "ip",
							isfrag ? " [frag]" : "");

   if (len >= sizeof (buf) || len > (size_t) w)
	 return;

   out_setattr (ATTR_OFF);
   out_setcolor (ATTR_COLOR_CYAN,ATTR_COLOR_BLACK);
   out_gotoxy (x + (w - (int) len) / 2,y);
   out_puts (buf);
}

static void flow_draw (const struct flow *flow)
{
   gui.flows++;

   if (gui.y > gui.height - 4)
	 return;

   drawaddr (2,
			 gui.y,
			 gui.column[0] - 2,
			 flow->saddr,flow->sport);

   drawaddr (gui.column[0] + 2,
			 gui.y,
			 gui.column[1] - gui.column[0] - 2,
			 flow->daddr,flow->dport);

   drawproto (gui.column[1] + 2,
			  gui.y,
			  gui.column[2] - gui.column[1] - 2,
			  flow->proto,flow->flags & FLOW_FRAG);

   drawrate (gui.column[2] + 1,
			 gui.y,
			 gui.width - gui.column[2] - 3,
			 flow->bitrate);

   gui.y++;
}

static void gui_flows (void)
{
   size_t i;

   out_setattr (ATTR_BOLD);
   out_setcolor (ATTR_COLOR_BLUE,ATTR_COLOR_BLACK);
   hline (1,gui.width - 2,2);
   PUTC_AT (line.lt,0,2);
   PUTC_AT (line.rt,gui.width - 1,2);

   gui.column[2] = gui.width - 12;
   gui.column[1] = gui.column[2] - 14;
   gui.column[0] = gui.column[1] / 2;

   for (i = 0; i < ARRAYSIZE (gui.column); i++)
	 {
		vline (gui.column[i],1,gui.height - 4);
		PUTC_AT (line.tt,gui.column[i],0);
		PUTC_AT (line.ct,gui.column[i],2);
		PUTC_AT (line.bt,gui.column[i],gui.height - 3);
	 }

   out_setcolor (ATTR_COLOR_MAGENTA,ATTR_COLOR_BLACK);
   PUTS_AT ("Source",2,1);
   PUTS_AT ("Destination",gui.column[0] + 2,1);
   PUTS_AT ("Protocol",gui.column[1] + 3,1);
   PUTS_AT ("Avg Rate",gui.column[2] + 2,1);

   gui.y = 3, gui.flows = 0;
   flow_process (flow_draw);
}

static void gui_help (void)
{
   static const struct
	 {
		const char *key;
		const char *msg;
	 } help[] =
	 {
		{ "^L", "Redraw the screen" },
		{ "h or ?", "Print this list" },
		{ "q", "Quit" }
	 };
   static const char *const msg[] =
	 {
		"Traffic is aggregated into flows keyed on the IP protocol, type of",
		"service, source and destination address, and source and destination",
		"port. Flows are listed by average rate, highest first, and only as",
		"many as fit on the screen are shown.",
		"",
		"Rates are in bits per second, averaged over the lifetime of the flow,",
		"so a flow that has just been created reads low until it has been up",
		"for a while. Fragmented datagrams are marked [frag]; their ports are",
		"only known once the first fragment has been seen."
	 };
   size_t i;
   int y;

   out_setattr (ATTR_BOLD);
   out_setcolor (ATTR_COLOR_MAGENTA,ATTR_COLOR_BLACK);
   PUTS_AT ("Interactive commands",2,2);

   for (i = 0, y = 4; i < ARRAYSIZE (help) && y <= gui.height - 4; i++, y++)
	 {
		out_setattr (ATTR_BOLD);
		out_setcolor (ATTR_COLOR_WHITE,ATTR_COLOR_BLACK);
		out_gotoxy (4,y);
		out_printf ("%-9s",help[i].key);

		out_setattr (ATTR_OFF);
		out_setcolor (ATTR_COLOR_CYAN,ATTR_COLOR_BLACK);
		out_puts (help[i].msg);
	 }

   if ((y += 1) > gui.height - 4)
	 return;

   out_setattr (ATTR_BOLD);
   out_setcolor (ATTR_COLOR_MAGENTA,ATTR_COLOR_BLACK);
   PUTS_AT ("About the display",2,y);

   out_setattr (ATTR_OFF);
   out_setcolor (ATTR_COLOR_CYAN,ATTR_COLOR_BLACK);

   for (i = 0, y += 2; i < ARRAYSIZE (msg) && y <= gui.height - 4; i++, y++)
	 {
		char buf[256];
		int room = gui.width - 5;

		if (room <= 0)
		  break;

		/* truncate rather than drop: a missing line reads as a bug */
		snprintf (buf,sizeof (buf),"%.*s",room,msg[i]);
		PUTS_AT (buf,4,y);
	 }
}

static void drawstatus (void)
{
   char buf[128];
   time_t now = time (NULL);
   struct tm tm;
   int len,room;

   out_setattr (ATTR_OFF);
   out_setcolor (ATTR_COLOR_MAGENTA,ATTR_COLOR_BLACK);

   room = gui.width - 14;

   /*
	* Longest form that fits, rather than nothing at all. The clock keeps
	* the last ten columns to itself.
	*/

   if (gui.display == gui_help)
	 {
		len = snprintf (buf,sizeof (buf),"potion %s - press any key to continue",POTION_VERSION);

		if (len > room)
		  len = snprintf (buf,sizeof (buf),"potion %s",POTION_VERSION);
	 }
   else
	 {
		uint64_t dropped = capture_dropped ();

		len = dropped != 0 ?
		  snprintf (buf,sizeof (buf),"potion %s - %zu flow%s - %" PRIu64 " dropped - press h for help",
					POTION_VERSION,gui.flows,gui.flows == 1 ? "" : "s",dropped) :
		  snprintf (buf,sizeof (buf),"potion %s - %zu flow%s - press h for help",
					POTION_VERSION,gui.flows,gui.flows == 1 ? "" : "s");

		if (len > room)
		  len = snprintf (buf,sizeof (buf),"potion %s - %zu flow%s",
						  POTION_VERSION,gui.flows,gui.flows == 1 ? "" : "s");

		if (len > room)
		  len = snprintf (buf,sizeof (buf),"potion %s",POTION_VERSION);
	 }

   if (len > 0 && len <= room)
	 PUTS_AT (buf,2,gui.height - 2);

   if (localtime_r (&now,&tm) != NULL &&
	   strftime (buf,sizeof (buf),"%H:%M:%S",&tm) > 0)
	 {
		out_setcolor (ATTR_COLOR_WHITE,ATTR_COLOR_BLACK);
		PUTS_AT (buf,gui.width - 10,gui.height - 2);
	 }
}

static void drawframe (void)
{
   out_setattr (ATTR_BOLD);
   out_setcolor (ATTR_COLOR_BLUE,ATTR_COLOR_BLACK);

   hline (1,gui.width - 2,0);
   hline (1,gui.width - 2,gui.height - 3);
   hline (1,gui.width - 2,gui.height - 1);

   vline (0,1,gui.height - 2);
   vline (gui.width - 1,1,gui.height - 2);

   PUTC_AT (line.tl,0,0);
   PUTC_AT (line.tr,gui.width - 1,0);
   PUTC_AT (line.lt,0,gui.height - 3);
   PUTC_AT (line.rt,gui.width - 1,gui.height - 3);
   PUTC_AT (line.bl,0,gui.height - 1);
   PUTC_AT (line.br,gui.width - 1,gui.height - 1);
}

static void gui_display (void)
{
   gui.width = out_width ();
   gui.height = out_height ();

   out_clear ();

   if (gui.width < MIN_WIDTH || gui.height < MIN_HEIGHT)
	 {
		out_setattr (ATTR_BOLD);
		out_setcolor (ATTR_COLOR_RED,ATTR_COLOR_BLACK);
		out_gotoxy (0,0);
		out_printf ("terminal too small (need %dx%d)",MIN_WIDTH,MIN_HEIGHT);
		out_flush ();
		return;
	 }

   drawframe ();
   gui.display ();
   drawstatus ();
   out_flush ();
}

/* libevent's diagnostics, mapped onto ours */
static void gui_event_log (int severity,const char *msg)
{
   log_printf (severity >= _EVENT_LOG_ERR ? LOG_LEVEL_ERROR : LOG_LEVEL_WARNING,
			   "libevent: %s\n",msg);
}

static void gui_dispatch (int fd,short event,void *arg)
{
   struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
   int c;

   (void) fd;
   (void) arg;

   if (event & EV_READ)
	 {
		int keys = 0;

		while (keys < KEY_BUDGET && (c = in_getc ()) >= 0)
		  {
			 keys++;

			 if (in_isresize (c))
			   {
				  out_refresh ();
				  continue;
			   }

			 if (gui.display != gui_flows)
			   {
				  gui.display = gui_flows;
				  continue;
			   }

			 if (c == KEY_CTRL ('l'))
			   out_refresh ();
			 else if (c == 'h' || c == '?')
			   gui.display = gui_help;
			 else if (c == 'q')
			   {
				  gui_close ();
				  return;
			   }
			 else out_beep ();
		  }

		/*
		 * A terminal that reports itself readable but never yields a key
		 * has hung up. An incomplete escape sequence looks the same for
		 * a moment, hence the allowance.
		 */

		if (keys != 0)
		  gui.empty_reads = 0;
		else if (++gui.empty_reads >= EMPTY_READ_LIMIT)
		  {
			 log_printf (LOG_LEVEL_ERROR,"terminal closed\n");
			 gui_close ();
			 return;
		  }
	 }

   gui_display ();

   evtimer_del (&gui.timer);
   evtimer_add (&gui.timer,&tv);
}

int gui_open (const struct config *config)
{
   struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

   sig_open ();

   event_set (&gui.event,STDIN_FILENO,EV_READ | EV_PERSIST,gui_dispatch,NULL);

   if (event_add (&gui.event,NULL))
	 {
		log_printf (LOG_LEVEL_ERROR,"failed to add terminal event handler\n");
		sig_close ();
		return (-1);
	 }

   evtimer_set (&gui.timer,gui_dispatch,NULL);
   evtimer_add (&gui.timer,&tv);

   gui.display = gui_flows;

   if (io_open ())
	 {
		log_printf (LOG_LEVEL_ERROR,"failed to initialise the terminal\n");
		evtimer_del (&gui.timer);
		event_del (&gui.event);
		sig_close ();
		return (-1);
	 }

   /*
	* libevent writes its warnings straight to stderr by default, which
	* would punch holes in the display; route them through the log too.
	*/
   event_set_log_callback (gui_event_log);

   /*
	* ncurses owns the terminal from here on, so diagnostics have to go
	* to syslog. Everything that could go wrong during startup has
	* already had its say on stderr.
	*/
   if (log_open_syslog (config->progname,config->facility,LOG_LEVEL_NORMAL))
	 {
		io_close ();
		evtimer_del (&gui.timer);
		event_del (&gui.event);
		sig_close ();
		log_printf (LOG_LEVEL_ERROR,"failed to open syslog: %s\n",strerror (errno));
		return (-1);
	 }

   gui_display ();

   return (0);
}

void gui_close (void)
{
   static volatile sig_atomic_t called = 0;

   if (!called)
	 {
		called = 1;
		evtimer_del (&gui.timer);
		event_del (&gui.event);
		io_close ();
		capture_close ();
		sig_close ();
	 }
}
