/*
 * support/nfs/rmtab.c
 *
 * Handling for rmtab.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"

#include <sys/fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include "nfslib.h"

static FILE	*rmfp = NULL;

int
setrmtabent(char *type)
{
	if (rmfp)
		fclose(rmfp);
	rmfp = fsetrmtabent(_PATH_RMTAB, type);
	return (rmfp != NULL);
}

FILE *
fsetrmtabent(char *fname, char *type)
{
	int	readonly = !strcmp(type, "r");
	FILE	*fp;

	if (!fname)
		return NULL;
	if ((fp = fopen(fname, type)) == NULL) {
		xlog(L_ERROR, "can't open %s for %sing", fname,
				readonly ? "read" : "writ");
		return NULL;
	}
	return fp;
}

struct rmtabent *
getrmtabent(int log)
{
	return fgetrmtabent(rmfp, log);
}

struct rmtabent *
fgetrmtabent(FILE *fp, int log)
{
	static struct rmtabent	re;
	char	buf[2048], *sp;

	errno = 0;
	if (!fp)
		return NULL;
	do {
		if (fgets(buf, sizeof(buf)-1, fp) == NULL)
			return NULL;
		if ((sp = strchr(buf, '\n')) != NULL)
			*sp = '\0';
		if (!(sp = strchr(buf, ':'))) {
			if (log)
				xlog(L_ERROR, "malformed entry in rmtab file");
			errno = EINVAL;
			return NULL;
		}
		*sp++ = '\0';
	} while (0);
	strncpy(re.r_client, buf, sizeof (re.r_client) - 1);
	re.r_client[sizeof (re.r_client) - 1] = '\0';
	strncpy(re.r_path, sp, sizeof (re.r_path) - 1);
	re.r_path[sizeof (re.r_path) - 1] = '\0';
	return &re;
}

void
putrmtabent(struct rmtabent *rep)
{
	fputrmtabent(rmfp, rep);
}

void
fputrmtabent(FILE *fp, struct rmtabent *rep)
{
	if (!fp)
		return;
	fprintf(fp, "%s:%s\n", rep->r_client, rep->r_path);
}

void
endrmtabent(void)
{
	fendrmtabent(rmfp);
	rmfp = NULL;
}

void
fendrmtabent(FILE *fp)
{
	if (fp)
		fclose(fp);
}

void
rewindrmtabent(void)
{
	if (rmfp)
		rewind(rmfp);
}

void
frewindrmtabent(FILE *fp)
{
	if (fp)
		rewind (fp);
}
