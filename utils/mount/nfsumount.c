/*
 * nfsumount.c -- Linux NFS umount
 * Copyright (C) 2006 Amit Gud <agud@redhat.com>
 *
 * - Basic code and wrapper around NFS umount code originally
 *   in util-linux/mount/nfsmount.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <mntent.h>
#include <sys/mount.h>
#include <ctype.h>

#include "xcommon.h"
#include "fstab.h"
#include "nls.h"
#include "conn.h"

#include "mount_constants.h"
#include "mount.h"
#include "nfsumount.h"

#if !defined(MNT_FORCE)
/* dare not try to include <linux/mount.h> -- lots of errors */
#define MNT_FORCE 1
#endif

#if !defined(MNT_DETACH)
#define MNT_DETACH 2
#endif

extern char *progname;
extern int nfs_mount_version;
extern int nomtab;
extern int verbose;
int force;
int lazy;
int remount;

extern int find_kernel_nfs_mount_version(void);
extern int probe_mntport(clnt_addr_t *);
extern int nfs_gethostbyname(const char *, struct sockaddr_in *);

static inline enum clnt_stat
nfs3_umount(dirpath *argp, CLIENT *clnt)
{
	static char clnt_res;
	memset (&clnt_res, 0, sizeof(clnt_res));
	return clnt_call(clnt, MOUNTPROC_UMNT,
			 (xdrproc_t) xdr_dirpath, (caddr_t)argp,
			 (xdrproc_t) xdr_void, (caddr_t) &clnt_res,
			 TIMEOUT);
}

static inline enum clnt_stat
nfs2_umount(dirpath *argp, CLIENT *clnt)
{
	static char clnt_res;
	memset (&clnt_res, 0, sizeof(clnt_res));
	return clnt_call(clnt, MOUNTPROC_UMNT,
			 (xdrproc_t) xdr_dirpath, (caddr_t)argp,
			 (xdrproc_t) xdr_void, (caddr_t) &clnt_res,
			 TIMEOUT);
}

int nfs_call_umount(clnt_addr_t *mnt_server, dirpath *argp)
{
	CLIENT *clnt;
	enum clnt_stat res = 0;
	int msock;

	clnt = mnt_openclnt(mnt_server, &msock);
	if (!clnt)
		goto out_bad;
	switch (mnt_server->pmap.pm_vers) {
	case 3:
		res = nfs3_umount(argp, clnt);
		break;
	case 2:
	case 1:
		res = nfs2_umount(argp, clnt);
		break;
	default:
		break;
	}
	mnt_closeclnt(clnt, msock);
	if (res == RPC_SUCCESS)
		return 1;
 out_bad:
	return 0;
}

u_int get_mntproto(const char *);
u_int
get_mntproto(const char *dirname)
{
	FILE *mtab;
	struct mntent mntbuf;
	char tmpbuf[BUFSIZ];
	u_int proto = IPPROTO_TCP; /* assume tcp */

	 mtab = setmntent ("/proc/mounts", "r");
	 if (mtab == NULL)
	 	mtab = setmntent (_PATH_MOUNTED, "r");
	if (mtab == NULL)
		return proto;

	while(getmntent_r(mtab, &mntbuf, tmpbuf, sizeof (tmpbuf))) {
		if (strcmp(mntbuf.mnt_type, "nfs"))
			continue;
		if (strcmp(dirname,  mntbuf.mnt_fsname))
			continue;
		if (hasmntopt(&mntbuf, "udp"))
			proto = IPPROTO_UDP;
		break;
	}
	endmntent (mtab);

	return proto;
}

/* complain about a failed umount */
static void complain(int err, const char *dev) {
  switch (err) {
    case ENXIO:
      nfs_error (_("umount: %s: invalid block device"), dev); break;
    case EINVAL:
      nfs_error (_("umount: %s: not mounted"), dev); break;
    case EIO:
      nfs_error (_("umount: %s: can't write superblock"), dev); break;
    case EBUSY:
     /* Let us hope fstab has a line "proc /proc ..."
        and not "none /proc ..."*/
      nfs_error (_("umount: %s: device is busy"), dev); break;
    case ENOENT:
      nfs_error (_("umount: %s: not found"), dev); break;
    case EPERM:
      nfs_error (_("umount: %s: must be superuser to umount"), dev); break;
    case EACCES:
      nfs_error (_("umount: %s: block devices not permitted on fs"), dev); break;
    default:
      nfs_error (_("umount: %s: %s"), dev, strerror (err)); break;
  }
}

int add_mtab2(const char *spec, const char *node, const char *type,
		const char *opts, struct mntentchn *mc)
{
	int umnt_err, umnt_err2, res;

        umnt_err = umnt_err2 = 0;
        if (lazy) {
                res = umount2 (node, MNT_DETACH);
                if (res < 0)
                        umnt_err = errno;
                goto writemtab;
        }

        if (force) {
                res = umount2 (node, MNT_FORCE);
                if (res == -1) {
                        int errsv = errno;
                        perror("umount2");
                        errno = errsv;
                        if (errno == ENOSYS) {
                                if (verbose)
                                        printf(_("no umount2, trying umount...\n"));
                                res = umount (node);
                        }
                }
        } else
                res = umount (node);

        if (res < 0) {
                umnt_err = errno;
                /* A device might have been mounted on a node that has since
                   been deleted or renamed, so if node fails, also try spec. */
                /* Note that this is incorrect in case spec was mounted
                   several times. */
                /* if (umnt_err == ENOENT || umnt_err == EINVAL) */
                if (umnt_err != EBUSY && strcmp(node, spec)) {
                        if (verbose)
                                printf (_("could not umount %s - trying %s instead\n"),
                                        node, spec);
                        res = umount (spec);
                        if (res < 0)
                                umnt_err2 = errno;
                       /* Do not complain about remote NFS mount points */
                        if (errno == ENOENT && index(spec, ':'))
                                umnt_err2 = 0;
                }
        }

        if (res < 0 && remount && (umnt_err == EBUSY || umnt_err2 == EBUSY)) {
                /* Umount failed - let us try a remount */
                res = mount(spec, node, NULL,
                            MS_MGC_VAL | MS_REMOUNT | MS_RDONLY, NULL);
                if (res == 0) {
                        nfs_mntent_t remnt;
                        fprintf(stderr,
                                _("umount: %s busy - remounted read-only\n"),
                                spec);
                        remnt.mnt_type = remnt.mnt_fsname = NULL;
                        remnt.mnt_dir = xstrdup(node);
                        remnt.mnt_opts = xstrdup("ro");
                        if (!nomtab)
                                update_mtab(node, &remnt);
                        return 0;
                } else if (errno != EBUSY) {    /* hmm ... */
                        perror("remount");
                        fprintf(stderr,
                                _("umount: could not remount %s read-only\n"),
                                spec);
                }
        }

        if (res >= 0) {
                /* Umount succeeded */
                if (verbose)
                        printf (_("%s umounted\n"), spec);
        }

 writemtab:
        if (!nomtab &&
            (umnt_err == 0 || umnt_err == EINVAL || umnt_err == ENOENT)) {
               update_mtab (node, NULL);
        }

        if (res >= 0)
                return 0;

        if (umnt_err2)
                complain(umnt_err2, spec);
        if (umnt_err && umnt_err != umnt_err2)
                complain(umnt_err, node);
        return 1;
}

/*
 * Returns 1 if everything went well, else 0.
 */
int _nfsumount(const char *spec, const char *opts)
{
	char *hostname;
	char *dirname;
	clnt_addr_t mnt_server = { &hostname, };
	struct pmap *pmap = &mnt_server.pmap;
	char *p;

	nfs_mount_version = find_kernel_nfs_mount_version();
	if (spec == NULL || (p = strchr(spec,':')) == NULL)
		goto out_bad;
	hostname = xstrndup(spec, p-spec);
	dirname = xstrdup(p+1);
#ifdef NFS_MOUNT_DEBUG
	printf(_("host: %s, directory: %s\n"), hostname, dirname);
#endif

	if (opts && (p = strstr(opts, "addr="))) {
		char *q;

		free(hostname);
		p += 5;
		q = p;
		while (*q && *q != ',') q++;
		hostname = xstrndup(p,q-p);
	}

	if (opts && (p = strstr(opts, "mounthost="))) {
		char *q;

		free(hostname);
		p += 10;
		q = p;
		while (*q && *q != ',') q++;
		hostname = xstrndup(p,q-p);
	}

	pmap->pm_prog = MOUNTPROG;
	pmap->pm_vers = MOUNTVERS;
	pmap->pm_prot = get_mntproto(spec);
	if (opts && (p = strstr(opts, "mountprog=")) && isdigit(*(p+10)))
		pmap->pm_prog = atoi(p+10);
	if (opts && (p = strstr(opts, "mountport=")) && isdigit(*(p+10)))
		pmap->pm_port = atoi(p+10);
	if (opts && (p = strstr(opts, "nfsvers=")) && isdigit(*(p+8)))
		pmap->pm_vers = nfsvers_to_mnt(atoi(p+8));
	if (opts && (p = strstr(opts, "mountvers=")) && isdigit(*(p+10)))
		pmap->pm_vers = atoi(p+10);

	if (!nfs_gethostbyname(hostname, &mnt_server.saddr))
		goto out_bad;
	if (!probe_mntport(&mnt_server))
		goto out_bad;
	return nfs_call_umount(&mnt_server, &dirname);
 out_bad:
	printf("%s: %s: not found or not mounted\n", progname, spec);
	return 0;
}

static struct option umount_longopts[] =
{
  { "force", 0, 0, 'f' },
  { "help", 0, 0, 'h' },
  { "no-mtab", 0, 0, 'n' },
  { "verbose", 0, 0, 'v' },
  { "read-only", 0, 0, 'r' },
  { NULL, 0, 0, 0 }
};

void umount_usage()
{
	printf("usage: %s dir [-fvnrlh]\n", progname);
	printf("options:\n\t-f\t\tforce unmount\n");
	printf("\t-v\t\tverbose\n");
	printf("\t-n\t\tDo not update /etc/mtab\n");
	printf("\t-r\t\tremount\n");
	printf("\t-l\t\tlazy unmount\n");
	printf("\t-h\t\tprint this help\n\n");
}

int nfsumount(int argc, char *argv[])
{
	int c, ret;
	char *spec;
	struct mntentchn *mc;

	spec = argv[1];

	argv += 1;
	argc -= 1;

	while ((c = getopt_long (argc, argv, "fvnrlh",
				umount_longopts, NULL)) != -1) {

		switch (c) {
		case 'f':
			++force;
			break;
		case 'v':
			++verbose;
			break;
		case 'n':
			++nomtab;
			break;
		case 'r':
			++remount;
			break;
		case 'l':
			++lazy;
			break;
		case 'h':
		default:
			umount_usage();
			return 0;
		}
	}

	mc = getmntdirbackward(spec, NULL);
	if (!mc)
		mc = getmntdevbackward(spec, NULL);
	if (!mc && verbose)
		printf(_("Could not find %s in mtab\n"), spec);

	if(mc) {
		ret = _nfsumount(mc->m.mnt_fsname, mc->m.mnt_opts);
		if(ret)
			ret = add_mtab2(mc->m.mnt_fsname, mc->m.mnt_dir,
				mc->m.mnt_type, mc->m.mnt_opts, mc);
	}
	else {
		ret = _nfsumount(spec, NULL);
		if(ret)
			ret = add_mtab2(spec, spec, spec, spec, NULL);
	}

	return(ret);
}

