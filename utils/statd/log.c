/*
 * Copyright (C) 1995 Olaf Kirch
 * Modified by Jeffrey A. Uphoff, 1995, 1997, 1999.
 * Modified by H.J. Lu, 1998.
 *
 * NSM for Linux.
 */

/* 
 * 	log.c - logging functions for lockd/statd
 *	260295	 okir	started with simply syslog logging.
 */

#include "config.h"

#include <syslog.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/types.h>
#include "log.h"

static char	progname[256];
static pid_t	mypid;
                                /* Turns on logging to console/stderr. */
static int	opt_debug = 0;	/* Will be command-line option, eventually */

void
log_init(char *name)
{
    char	*sp;

    openlog(name, LOG_PID, LOG_LOCAL5);
    if ((sp = strrchr(name, '/')) != NULL)
	name = ++sp;
    strncpy(progname, name, sizeof (progname) - 1);
    progname[sizeof (progname) - 1] = '\0';
    mypid = getpid();
}

void
log_background(void)
{
    /* NOP */
}

void
log_enable(int level)
{
    opt_debug = 1;
}

int
log_enabled(int level)
{
    return opt_debug;
}

void
die(char *fmt, ...)
{
    char	buffer[1024];
    va_list	ap;

    va_start(ap, fmt);
    vsnprintf (buffer, 1024, fmt, ap);
    va_end(ap);
    buffer[1023]=0;

    log(L_FATAL, "%s", buffer);

#ifndef DEBUG
    exit (2);
#else
    abort();	/* make a core */
#endif
}

void
log(int level, char *fmt, ...)
{
    char	buffer[1024];
    va_list	ap;

    va_start(ap, fmt);
    vsnprintf (buffer, 1024, fmt, ap);
    va_end(ap);
    buffer[1023]=0;

    if (level < L_DEBUG) {
    	syslog(level, "%s", buffer);
    }

    if (opt_debug) {
        time_t		now;
        struct tm *	tm;

        time(&now);
        tm = localtime(&now);
        fprintf (stderr, "%02d.%02d.%02d %02d:%02d:%02d %s[%d]: %s\n",
			tm->tm_mday, tm->tm_mon, tm->tm_year,
			tm->tm_hour, tm->tm_min, tm->tm_sec,
			progname, mypid,
			buffer);
    }
}
