/*
 * support/nfs/keytab.c
 *
 * Manage the nfskeys database.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <ctype.h>
#include "xmalloc.h"
#include "nfslib.h"
#include "exportfs.h"
#include "xio.h"

static FILE	*cfp = NULL;

int
setnfskeyent(char *fname)
{
	if (cfp)
		fclose(cfp);
	if (!fname)
		fname = _PATH_NFSKEYS;
	cfp = fsetnfskeyent(fname, "r");
	return cfp != NULL;
}

FILE *
fsetnfskeyent(char *fname, char *type)
{
#if 0
	FILE	*fp;

	if ((fp = fopen(fname, type)) == NULL)
		xlog(L_ERROR, "can't open %s for %sing\n",
				fname, type[0] == 'r'? "read" : "writ");
	return fp;
#else
	return fopen(fname, type);
#endif
}

struct nfskeyent *
getnfskeyent(void)
{
	return fgetnfskeyent(cfp);
}

struct nfskeyent *
fgetnfskeyent(FILE *fp)
{
	static struct nfskeyent ke;

	if (!fp)
		return NULL;

	do {
		if (fread(&ke, sizeof(ke), 1, fp) != 1)
			return NULL;
	} while(ke.k_hostname[0] == '\0');
	return &ke;
}

void
endnfskeyent(void)
{
	if (cfp)
		fclose(cfp);
	cfp = NULL;
}

void
fendnfskeyent(FILE *fp)
{
	if (fp)
		fclose(fp);
}

void
fputnfskeyent(FILE *fp, struct nfskeyent *kep)
{
	fwrite(kep, sizeof(*kep), 1, fp);
}

int
getnfskeytype(char *st)
{
	if (!strcasecmp(st, "null"))
		return CLE_KEY_NULL;
	if (!strcasecmp(st, "md5"))
		return CLE_KEY_MD5;
	if (!strcasecmp(st, "sha"))
		return CLE_KEY_SHA;
	return CLE_KEY_NONE;
}

char *
getnfskeyname(int type)
{
	switch (type) {
	case CLE_KEY_NONE:
		return "none";
	case CLE_KEY_NULL:
		return "null";
	case CLE_KEY_MD5:
		return "md5";
	case CLE_KEY_SHA:
		return "sha";
	}
	return "unk";
}

int
getnfskeysize(int type)
{
	switch (type) {
	case CLE_KEY_MD5:
		return 16;
	case CLE_KEY_SHA:
		return 20;
	}
	return 0;
}
