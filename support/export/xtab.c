/*
 * support/export/xtab.c
 *
 * Interface to the xtab file.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"

#include <sys/fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "xmalloc.h"
#include "nfslib.h"
#include "exportfs.h"
#include "xio.h"
#include "xlog.h"

static int
xtab_read(char *xtab, int is_export)
{
	struct exportent	*xp;
	nfs_export		*exp;
	int			lockid;

	if ((lockid = xflock(xtab, "r")) < 0)
		return 0;
	setexportent(xtab, "r");
	while ((xp = getexportent()) != NULL) {
		if (!(exp = export_lookup(xp->e_hostname, xp->e_path)) &&
		    !(exp = export_create(xp))) {
			continue;
		}
		if (is_export) {
			exp->m_xtabent = 1;
			exp->m_mayexport = 1;
		} else
			exp->m_exported = 1;
	}
	endexportent();
	xfunlock(lockid);

	return 0;
}

int
xtab_mount_read(void)
{
	int fd;
	if ((fd=open(_PATH_PROC_EXPORTS, O_RDONLY))>=0) {
		close(fd);
		return xtab_read(_PATH_PROC_EXPORTS, 0);
	} else
		return xtab_read(_PATH_XTAB, 0);
}

int
xtab_export_read(void)
{
	return xtab_read(_PATH_ETAB, 1);
}

static int
xtab_write(char *xtab, char *xtabtmp, int is_export)
{
	struct exportent	xe;
	nfs_export		*exp;
	int			lockid, i;

	if ((lockid = xflock(xtab, "w")) < 0) {
		xlog(L_ERROR, "can't lock %s for writing", xtab);
		return 0;
	}
	setexportent(xtabtmp, "w");

	for (i = 0; i < MCL_MAXTYPES; i++) {
		for (exp = exportlist[i]; exp; exp = exp->m_next) {
			if (is_export && !exp->m_xtabent)
				continue;
			if (!is_export && ! exp->m_exported)
				continue;

			/* write out the export entry using the FQDN */
			xe = exp->m_export;
			strncpy(xe.e_hostname,
				exp->m_client->m_hostname,
				sizeof (xe.e_hostname) - 1);
			xe.e_hostname[sizeof (xe.e_hostname) - 1] = '\0';
			putexportent(&xe);
		}
	}
	endexportent();

	rename(xtabtmp, xtab);

	xfunlock(lockid);

	return 1;
}

int
xtab_export_write()
{
	return xtab_write(_PATH_ETAB, _PATH_ETABTMP, 1);
}

int
xtab_mount_write()
{
	return xtab_write(_PATH_XTAB, _PATH_XTABTMP, 0);
}

void
xtab_append(nfs_export *exp)
{
	struct exportent xe;
	int		lockid;

	if ((lockid = xflock(_PATH_XTAB, "w")) < 0)
		return;
	setexportent(_PATH_XTAB, "a");
	xe = exp->m_export;
	strncpy(xe.e_hostname, exp->m_client->m_hostname,
	       sizeof (xe.e_hostname) - 1);
	xe.e_hostname[sizeof (xe.e_hostname) - 1] = '\0';
	putexportent(&xe);
	endexportent();
	xfunlock(lockid);
	exp->m_xtabent = 1;
}

