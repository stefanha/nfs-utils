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

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <mntent.h>
#include <sys/mount.h>
#include <ctype.h>
#include <pwd.h>

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
nfs_umount(dirpath *argp, CLIENT *clnt)
{
	return clnt_call(clnt, MOUNTPROC_UMNT,
			 (xdrproc_t) xdr_dirpath, (caddr_t)argp,
			 (xdrproc_t) xdr_void, NULL,
			 TIMEOUT);
}

int nfs_call_umount(clnt_addr_t *mnt_server, dirpath *argp)
{
	CLIENT *clnt;
	enum clnt_stat res = 0;
	int msock;

	switch (mnt_server->pmap.pm_vers) {
	case 3:
	case 2:
	case 1:
		if (!probe_mntport(mnt_server))
			goto out_bad;
		clnt = mnt_openclnt(mnt_server, &msock);
		if (!clnt)
			goto out_bad;
		res = nfs_umount(argp, clnt);
		mnt_closeclnt(clnt, msock);
		if (res == RPC_SUCCESS)
			return 1;
		break;
	default:
		res = 1;
		break;
	}
 out_bad:
	return res;
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

int del_mtab(const char *spec, const char *node)
{
	int umnt_err, res;

        umnt_err = 0;
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

        if (res < 0 && remount && errno == EBUSY && spec) {
                /* Umount failed - let us try a remount */
                res = mount(spec, node, NULL,
                            MS_MGC_VAL | MS_REMOUNT | MS_RDONLY, NULL);
                if (res == 0) {
                        struct mntent remnt;
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
                        printf (_("%s umounted\n"), spec ? spec : node);
        }

 writemtab:
        if (!nomtab &&
            (umnt_err == 0 || umnt_err == EINVAL || umnt_err == ENOENT)) {
               update_mtab(node, NULL);
        }

        if (res >= 0)
                return 0;

        if (umnt_err)
                complain(umnt_err, node);
        return 1;
}

/*
 * Returns 1 if everything went well, else 0.
 */
int _nfsumount(const char *spec, char *opts)
{
	char *hostname;
	char *dirname;
	clnt_addr_t mnt_server = { &hostname, };
	struct mntent mnt = { .mnt_opts = opts };
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
	pmap->pm_vers = MOUNTVERS_NFSV3;
	pmap->pm_prot = IPPROTO_TCP;
	if (opts && (p = strstr(opts, "mountprog=")) && isdigit(*(p+10)))
		pmap->pm_prog = atoi(p+10);
	if (opts && (p = strstr(opts, "mountport=")) && isdigit(*(p+10)))
		pmap->pm_port = atoi(p+10);
	if (opts && hasmntopt(&mnt, "v2"))
		pmap->pm_vers = nfsvers_to_mnt(2);
	if (opts && hasmntopt(&mnt, "v3"))
		pmap->pm_vers = nfsvers_to_mnt(3);
	if (opts && hasmntopt(&mnt, "v4"))
		pmap->pm_vers = nfsvers_to_mnt(4);
	if (opts && (p = strstr(opts, "vers=")) && isdigit(*(p+5)))
		pmap->pm_vers = nfsvers_to_mnt(atoi(p+5));
	if (opts && (p = strstr(opts, "mountvers=")) && isdigit(*(p+10)))
		pmap->pm_vers = atoi(p+10);
	if (opts && (hasmntopt(&mnt, "udp") || hasmntopt(&mnt, "proto=udp")))
		pmap->pm_prot = IPPROTO_UDP;

	if (!nfs_gethostbyname(hostname, &mnt_server.saddr))
		goto out_bad;
	return nfs_call_umount(&mnt_server, &dirname);
 out_bad:
	fprintf(stderr, "%s: %s: not found or not mounted\n", progname, spec);
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

	argv[0] = argv[-1]; /* So that getopt error messages are correct */
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
	if (optind != argc) {
		umount_usage();
		return 0;
	}
	
	if (spec == NULL || (*spec != '/' && strchr(spec,':') == NULL)) {
		printf(_("umount: %s: not found\n"), spec);
		return 0;
	}

	if (*spec == '/')
		mc = getmntdirbackward(spec, NULL);
	else
		mc = getmntdevbackward(spec, NULL);
	if (!mc && verbose)
		printf(_("Could not find %s in mtab\n"), spec);

	if (mc && strcmp(mc->m.mnt_type, "nfs") != 0 &&
	    strcmp(mc->m.mnt_type, "nfs4") != 0) {
		fprintf(stderr, "umount.nfs: %s on %s it not an nfs filesystem\n",
			mc->m.mnt_fsname, mc->m.mnt_dir);
		exit(1);
	}

	if (getuid() != 0) {
		/* only permitted if "user=" or "users" is in mount options */
		if (!mc) {
			/* umount might call us twice.  The second time there will
			 * be no entry in mtab and we should just exit quietly
			 */
			return 0;

		only_root:
			fprintf(stderr,"%s: You are not permitted to unmount %s\n",
				progname, spec);
			return 0;
		}
		if (hasmntopt(&mc->m, "users") == NULL) {
			char *opt = hasmntopt(&mc->m, "user");
			struct passwd *pw;
			char *comma;
			int len;
			if (!opt)
				goto only_root;
			if (opt[4] != '=')
				goto only_root;
			comma = strchr(opt, ',');
			if (comma)
				len = comma - (opt + 5);
			else
				len = strlen(opt+5);
			pw = getpwuid(getuid());
			if (pw == NULL || strlen(pw->pw_name) != len
			    || strncmp(pw->pw_name, opt+5, len) != 0)
				goto only_root;
		}
	}

	ret = 0;
	if (mc) {
		if (!lazy)
			_nfsumount(mc->m.mnt_fsname, mc->m.mnt_opts);
		ret = del_mtab(mc->m.mnt_fsname, mc->m.mnt_dir);
	} else if (*spec != '/') {
		if (!lazy)
			_nfsumount(spec, "tcp,v3");
	} else
		ret = del_mtab(NULL, spec);

	return(ret);
}

