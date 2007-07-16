/*
 * error.c -- Common error handling functions
 *
 * Copyright (C) 2007 Oracle.  All rights reserved.
 * Copyright (C) 2007 Chuck Lever <chuck.lever@oracle.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 *
 * To Do:
 *  + Proper support for internationalization
 */

#include "config.h"
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <rpc/rpc.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_clnt.h>

#include "xcommon.h"
#include "nls.h"
#include "mount.h"
#include "error.h"

#ifdef HAVE_RPCSVC_NFS_PROT_H
#include <rpcsvc/nfs_prot.h>
#else
#include <linux/nfs.h>
#define nfsstat nfs_stat
#endif

extern char *progname;

static char errbuf[BUFSIZ];
static char *erreob = &errbuf[BUFSIZ];

/* Convert RPC errors into strings */
static int rpc_strerror(int spos)
{
	int cf_stat = rpc_createerr.cf_stat;
	int pos = 0, cf_errno = rpc_createerr.cf_error.re_errno;
	char *ptr, *estr = clnt_sperrno(cf_stat);
	char *tmp;

	if (estr) {
		if ((ptr = index(estr, ':')))
			estr = ++ptr;

		tmp = &errbuf[spos];
		if (cf_stat == RPC_SYSTEMERROR)
			pos = snprintf(tmp, (erreob - tmp),
				"System Error: %s", strerror(cf_errno));
		else
			pos = snprintf(tmp, (erreob - tmp), "RPC Error:%s", estr);
	}
	return pos;
}

void mount_errors(char *server, int will_retry, int bg)
{
	int pos = 0;
	char *tmp;
	static int onlyonce = 0;

	tmp = &errbuf[pos];
	if (bg)
		pos = snprintf(tmp, (erreob - tmp),
			"mount to NFS server '%s' failed: ", server);
	else
		pos = snprintf(tmp, (erreob - tmp),
			"mount: mount to NFS server '%s' failed: ", server);

	tmp = &errbuf[pos];
	if (rpc_createerr.cf_stat == RPC_TIMEDOUT) {
		pos = snprintf(tmp, (erreob - tmp), "timed out %s",
			will_retry ? "(retrying)" : "(giving up)");
	} else {
		pos += rpc_strerror(pos);
		tmp = &errbuf[pos];
		if (bg) {
			pos = snprintf(tmp, (erreob - tmp), " %s",
				will_retry ? "(retrying)" : "(giving up)");
		}
	}
	if (bg) {
		if (onlyonce++ < 1)
			openlog("mount", LOG_CONS|LOG_PID, LOG_AUTH);
		syslog(LOG_ERR, "%s.", errbuf);
	} else
		fprintf(stderr, "%s.\n", errbuf);
}

void mount_error(const char *spec, const char *mount_point, int error)
{
	switch(error) {
	case ENOTDIR:
		nfs_error(_("%s: mount point %s is not a directory"),
				progname, mount_point);
		break;
	case EBUSY:
		nfs_error(_("%s: %s is already mounted or busy"),
			progname, mount_point);
		break;
	case ENOENT:
		if (spec)
			nfs_error(_("%s: mounting %s failed, "
				"reason given by server:\n  %s"),
				progname, spec, strerror(error));
		else
			nfs_error(_("%s: mount point %s does not exist"),
				progname, mount_point);
		break;
	default:
		nfs_error(_("%s: %s"),
			progname, strerror(error));
	}
}

/*
 * Report a failed umount
 */
void umount_error(int err, const char *dev)
{
	switch (err) {
	case ENXIO:
		nfs_error(_("%s: %s: invalid block device"),
			progname, dev);
		break;
	case EINVAL:
		nfs_error(_("%s: %s: not mounted"),
			progname, dev);
		break;
	case EIO:
		nfs_error(_("%s: %s: can't write superblock"),
			progname, dev);
		break;
	case EBUSY:
		nfs_error(_("%s: %s: device is busy"),
			progname, dev);
		break;
	case ENOENT:
		nfs_error(_("%s: %s: not found"),
			progname, dev);
		break;
	case EPERM:
		nfs_error(_("%s: %s: must be superuser to umount"),
			progname, dev);
		break;
	case EACCES:
		nfs_error(_("%s: %s: block devices not permitted on fs"),
			progname, dev);
		break;
	default:
		nfs_error(_("%s: %s: %s"),
			progname, dev, strerror(err));
		break;
	}
}

/*
 * We need to translate between nfs status return values and
 * the local errno values which may not be the same.
 *
 * Andreas Schwab <schwab@LS5.informatik.uni-dortmund.de>: change errno:
 * "after #include <errno.h> the symbol errno is reserved for any use,
 *  it cannot even be used as a struct tag or field name".
 */

#ifndef EDQUOT
#define EDQUOT	ENOSPC
#endif

static struct {
	enum nfsstat stat;
	int errnum;
} nfs_errtbl[] = {
	{ NFS_OK,		0		},
	{ NFSERR_PERM,		EPERM		},
	{ NFSERR_NOENT,		ENOENT		},
	{ NFSERR_IO,		EIO		},
	{ NFSERR_NXIO,		ENXIO		},
	{ NFSERR_ACCES,		EACCES		},
	{ NFSERR_EXIST,		EEXIST		},
	{ NFSERR_NODEV,		ENODEV		},
	{ NFSERR_NOTDIR,	ENOTDIR		},
	{ NFSERR_ISDIR,		EISDIR		},
#ifdef NFSERR_INVAL
	{ NFSERR_INVAL,		EINVAL		},	/* that Sun forgot */
#endif
	{ NFSERR_FBIG,		EFBIG		},
	{ NFSERR_NOSPC,		ENOSPC		},
	{ NFSERR_ROFS,		EROFS		},
	{ NFSERR_NAMETOOLONG,	ENAMETOOLONG	},
	{ NFSERR_NOTEMPTY,	ENOTEMPTY	},
	{ NFSERR_DQUOT,		EDQUOT		},
	{ NFSERR_STALE,		ESTALE		},
#ifdef EWFLUSH
	{ NFSERR_WFLUSH,	EWFLUSH		},
#endif
	/* Throw in some NFSv3 values for even more fun (HP returns these) */
	{ 71,			EREMOTE		},

	{ -1,			EIO		}
};

char *nfs_strerror(int stat)
{
	int i;
	static char buf[256];

	for (i = 0; nfs_errtbl[i].stat != -1; i++) {
		if (nfs_errtbl[i].stat == stat)
			return strerror(nfs_errtbl[i].errnum);
	}
	sprintf(buf, _("unknown nfs status return value: %d"), stat);
	return buf;
}
