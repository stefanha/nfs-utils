/*
 * support/nfs/xio.c
 * 
 * Simple I/O functions for the parsing of /etc/exports and /etc/nfsclients.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"

#include <sys/fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include "xmalloc.h"
#include "xlog.h"
#include "xio.h"

XFILE *
xfopen(char *fname, char *type)
{
	XFILE	*xfp;
	FILE	*fp;

	if (!(fp = fopen(fname, type)))
		return NULL;
	xfp = (XFILE *) xmalloc(sizeof(*xfp));
	xfp->x_fp = fp;
	xfp->x_line = 1;

	return xfp;
}

void
xfclose(XFILE *xfp)
{
	fclose(xfp->x_fp);
	xfree(xfp);
}

static void
doalarm(int sig)
{
	return;
}

int
xflock(char *fname, char *type)
{
	struct sigaction sa, oldsa;
	int		readonly = !strcmp(type, "r");
	struct flock	fl = { readonly? F_RDLCK : F_WRLCK, SEEK_SET, 0, 0, 0 };
	int		fd;

	if ((fd = open(fname, readonly? O_RDONLY : (O_RDWR|O_CREAT))) < 0) {
		xlog(L_WARNING, "could not open %s for locking", fname);
		return -1;
	}
	sa.sa_handler = doalarm;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGALRM, &sa, &oldsa);
	alarm(10);
	if (fcntl(fd, F_SETLKW, &fl) < 0) {
		alarm(0);
		xlog(L_WARNING, "failed to lock %s", fname);
		close(fd);
		fd = 0;
	} else {
		alarm(0);
	}
	sigaction(SIGALRM, &oldsa, NULL);

	return fd;
}

void
xfunlock(int fd)
{
	close(fd);
}

int
xgettok(XFILE *xfp, char sepa, char *tok, int len)
{
	int	i = 0;
	int	c = 0;

	while (i < len && (c = xgetc(xfp)) != EOF && c != sepa && !isspace(c))
		tok[i++] = c;
	if (c == '\n')
		xungetc(c, xfp);
	if (!i)
		return 0;
	if (i >= len || (sepa && c != sepa))
		return -1;
	tok[i] = '\0';
	return 1;
}

int
xgetc(XFILE *xfp)
{
	int	c = getc(xfp->x_fp);

	if (c == EOF)
		return c;
	if (c == '\\') {
		if ((c = getc(xfp->x_fp)) != '\n') {
			ungetc(c, xfp->x_fp);
			return '\\';
		}
		xfp->x_line++;
		while ((c = getc(xfp->x_fp)) == ' ' || c == '\t');
		ungetc(c, xfp->x_fp);
		return ' ';
	}
	if (c == '#')
		c = xskipcomment(xfp);
	if (c == '\n')
		xfp->x_line++;
	return c;
}

void
xungetc(int c, XFILE *xfp)
{
	if (c == EOF)
		return;

	ungetc(c, xfp->x_fp);
	if (c == '\n')
		xfp->x_line--;
}

void
xskip(XFILE *xfp, char *str)
{
	int	c;

	while ((c = xgetc(xfp)) != EOF && strchr(str, c));
	ungetc(c, xfp->x_fp);
}

char
xskipcomment(XFILE *xfp)
{
	int	c;

	while ((c = getc(xfp->x_fp)) != EOF && c != '\n');
	return c;
}
