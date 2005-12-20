/*
 * support/nfs/xlog.c
 *
 * This module handles the logging of requests.
 *
 * TODO:	Merge the two "XXX_log() calls.
 *
 * Authors:	Donald J. Becker, <becker@super.org>
 *		Rick Sladkey, <jrs@world.std.com>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Olaf Kirch, <okir@monad.swb.de>
 *
 *		This software maybe be used for any purpose provided
 *		the above copyright notice is retained.  It is supplied
 *		as is, with no warranty expressed or implied.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include "nfslib.h"

#undef	VERBOSE_PRINTF

static int  log_stderr = 1;
static int  log_syslog = 1;
static int  logging = 0;		/* enable/disable DEBUG logs	*/
static int  logmask = 0;		/* What will be logged		*/
static char log_name[256];		/* name of this program		*/
static int  log_pid = -1;		/* PID of this program		*/

static void	xlog_toggle(int sig);
static struct xlog_debugfac	debugnames[] = {
	{ "general",	D_GENERAL, },
	{ "call",	D_CALL, },
	{ "auth",	D_AUTH, },
	{ "parse",	D_PARSE, },
	{ "all",	D_ALL, },
	{ NULL,		0, },
};

void
xlog_open(char *progname)
{
	openlog(progname, LOG_PID, LOG_DAEMON);

	strncpy(log_name, progname, sizeof (log_name) - 1);
	log_name [sizeof (log_name) - 1] = '\0';
	log_pid = getpid();

	signal(SIGUSR1, xlog_toggle);
	signal(SIGUSR2, xlog_toggle);
}

void
xlog_stderr(int on)
{
	log_stderr = on;
}

void
xlog_syslog(int on)
{
	log_syslog = on;
}

static void
xlog_toggle(int sig)
{
	unsigned int	tmp, i;

	if (sig == SIGUSR1) {
		if ((logmask & D_ALL) && !logging) {
			xlog(D_GENERAL, "turned on logging");
			logging = 1;
			return;
		}
		tmp = ~logmask;
		logmask |= ((logmask & D_ALL) << 1) | D_GENERAL;
		for (i = -1, tmp &= logmask; tmp; tmp >>= 1, i++)
			if (tmp & 1)
				xlog(D_GENERAL,
					"turned on logging level %d", i);
	} else {
		xlog(D_GENERAL, "turned off logging");
		logging = 0;
	}
	signal(sig, xlog_toggle);
}

void
xlog_config(int fac, int on)
{
	if (on)
		logmask |= fac;
	else
		logmask &= ~fac;
	if (on)
		logging = 1;
}

void
xlog_sconfig(char *kind, int on)
{
	struct xlog_debugfac	*tbl = debugnames;

	while (tbl->df_name != NULL && strcasecmp(tbl->df_name, kind)) 
		tbl++;
	if (!tbl->df_name) {
		xlog (L_WARNING, "Invalid debug facility: %s\n", kind);
		return;
	}
	xlog_config(tbl->df_fac, on);
}

int
xlog_enabled(int fac)
{
	return (logging && (fac & logmask));
}


/* Write something to the system logfile and/or stderr */
void
xlog(int kind, const char *fmt, ...)
{
	char		buff[1024];
	va_list		args;
	int		n;

	if (!(kind & (L_ALL)) && !(logging && (kind & logmask)))
		return;

	va_start(args, fmt);
	vsnprintf(buff, sizeof (buff), fmt, args);
	va_end(args);

	if ((n = strlen(buff)) > 0 && buff[n-1] == '\n')
		buff[--n] = '\0';

	if (log_syslog) {
		switch (kind) {
		case L_FATAL:
			syslog(LOG_ERR, "%s", buff);
			break;
		case L_ERROR:
			syslog(LOG_ERR, "%s", buff);
			break;
		case L_WARNING:
			syslog(LOG_WARNING, "%s", buff);
			break;
		case L_NOTICE:
			syslog(LOG_NOTICE, "%s", buff);
			break;
		default:
			if (!log_stderr)
				syslog(LOG_INFO, "%s", buff);
			break;
		}
	}

	if (log_stderr) {
#ifdef VERBOSE_PRINTF
		time_t		now;
		struct tm	*tm;

		time(&now);
		tm = localtime(&now);
		fprintf(stderr, "%s[%d] %04d-%02d-%02d %02d:%02d:%02d %s\n",
				log_name, log_pid,
				tm->tm_year+1900, tm->tm_mon + 1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec,
				buff);
#else
		fprintf(stderr, "%s: %s\n", log_name, buff);
#endif
	}

	if (kind == L_FATAL)
		exit(1);
}
