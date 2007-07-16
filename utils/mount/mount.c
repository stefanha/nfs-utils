/*
 * mount.c -- Linux NFS mount
 *
 * Copyright (C) 2006 Amit Gud <agud@redhat.com>
 *
 * - Basic code and wrapper around mount and umount code of NFS.
 *   Based on util-linux/mount/mount.c.
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

#include "config.h"
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <getopt.h>
#include <mntent.h>
#include <pwd.h>

#include "fstab.h"
#include "xcommon.h"
#include "nls.h"
#include "mount_constants.h"
#include "nfs_paths.h"

#include "nfs_mount.h"
#include "nfs4_mount.h"
#include "nfsumount.h"
#include "mount.h"
#include "error.h"

char *progname;
int nfs_mount_data_version;
int nomtab;
int verbose;
int sloppy;

static struct option longopts[] = {
  { "fake", 0, 0, 'f' },
  { "help", 0, 0, 'h' },
  { "no-mtab", 0, 0, 'n' },
  { "read-only", 0, 0, 'r' },
  { "ro", 0, 0, 'r' },
  { "verbose", 0, 0, 'v' },
  { "version", 0, 0, 'V' },
  { "read-write", 0, 0, 'w' },
  { "rw", 0, 0, 'w' },
  { "options", 1, 0, 'o' },
  { NULL, 0, 0, 0 }
};

/* Map from -o and fstab option strings to the flag argument to mount(2).  */
struct opt_map {
  const char *opt;              /* option name */
  int  skip;                    /* skip in mtab option string */
  int  inv;                     /* true if flag value should be inverted */
  int  mask;                    /* flag mask value */
};

/* Custom mount options for our own purposes.  */
#define MS_DUMMY	0x00000000
#define MS_USERS	0x40000000
#define MS_USER		0x80000000

static const struct opt_map opt_map[] = {
  { "defaults", 0, 0, 0         },      /* default options */
  { "ro",       1, 0, MS_RDONLY },      /* read-only */
  { "rw",       1, 1, MS_RDONLY },      /* read-write */
  { "exec",     0, 1, MS_NOEXEC },      /* permit execution of binaries */
  { "noexec",   0, 0, MS_NOEXEC },      /* don't execute binaries */
  { "suid",     0, 1, MS_NOSUID },      /* honor suid executables */
  { "nosuid",   0, 0, MS_NOSUID },      /* don't honor suid executables */
  { "dev",      0, 1, MS_NODEV  },      /* interpret device files  */
  { "nodev",    0, 0, MS_NODEV  },      /* don't interpret devices */
  { "sync",     0, 0, MS_SYNCHRONOUS},  /* synchronous I/O */
  { "async",    0, 1, MS_SYNCHRONOUS},  /* asynchronous I/O */
  { "dirsync",  0, 0, MS_DIRSYNC},      /* synchronous directory modifications */
  { "remount",  0, 0, MS_REMOUNT},      /* Alter flags of mounted FS */
  { "bind",     0, 0, MS_BIND   },      /* Remount part of tree elsewhere */
  { "rbind",    0, 0, MS_BIND|MS_REC }, /* Idem, plus mounted subtrees */
  { "auto",     0, 0, MS_DUMMY },       /* Can be mounted using -a */
  { "noauto",   0, 0, MS_DUMMY },       /* Can  only be mounted explicitly */
  { "users",    1, 0, MS_USERS },	/* Allow ordinary user to mount */
  { "nousers",  0, 1, MS_DUMMY  },      /* Forbid ordinary user to mount */
  { "user",     1, 0, MS_USER  },	/* Allow ordinary user to mount */
  { "nouser",   0, 1, MS_DUMMY   },     /* Forbid ordinary user to mount */
  { "owner",    0, 0, MS_DUMMY  },      /* Let the owner of the device mount */
  { "noowner",  0, 0, MS_DUMMY  },      /* Device owner has no special privs */
  { "group",    0, 0, MS_DUMMY  },      /* Let the group of the device mount */
  { "nogroup",  0, 0, MS_DUMMY  },      /* Device group has no special privs */
  { "_netdev",  0, 0, MS_DUMMY},        /* Device requires network */
  { "comment",  0, 0, MS_DUMMY},        /* fstab comment only (kudzu,_netdev)*/

  /* add new options here */
#ifdef MS_NOSUB
  { "sub",      0, 1, MS_NOSUB  },      /* allow submounts */
  { "nosub",    0, 0, MS_NOSUB  },      /* don't allow submounts */
#endif
#ifdef MS_SILENT
  { "quiet",    0, 0, MS_SILENT    },   /* be quiet  */
  { "loud",     0, 1, MS_SILENT    },   /* print out messages. */
#endif
#ifdef MS_MANDLOCK
  { "mand",     0, 0, MS_MANDLOCK },    /* Allow mandatory locks on this FS */
  { "nomand",   0, 1, MS_MANDLOCK },    /* Forbid mandatory locks on this FS */
#endif
  { "loop",     1, 0, MS_DUMMY   },      /* use a loop device */
#ifdef MS_NOATIME
  { "atime",    0, 1, MS_NOATIME },     /* Update access time */
  { "noatime",  0, 0, MS_NOATIME },     /* Do not update access time */
#endif
#ifdef MS_NODIRATIME
  { "diratime", 0, 1, MS_NODIRATIME },  /* Update dir access times */
  { "nodiratime", 0, 0, MS_NODIRATIME },/* Do not update dir access times */
#endif
  { NULL,	0, 0, 0		}
};

#define MAKE_VERSION(p,q,r)	(65536 * (p) + 256 * (q) + (r))

int linux_version_code(void)
{
	struct utsname my_utsname;
	int p, q, r;

	if (uname(&my_utsname) == 0) {
		p = atoi(strtok(my_utsname.release, "."));
		q = atoi(strtok(NULL, "."));
		r = atoi(strtok(NULL, "."));
		return MAKE_VERSION(p,q,r);
	}
	return 0;
}

/*
 * Choose the version of the nfs_mount_data structure that is appropriate
 * for the kernel that is doing the mount.
 *
 * NFS_MOUNT_VERSION:		maximum version supported by these sources
 * nfs_mount_data_version:	maximum version supported by the running kernel
 */
static void discover_nfs_mount_data_version(void)
{
	int kernel_version = linux_version_code();

	if (kernel_version) {
		if (kernel_version < MAKE_VERSION(2, 1, 32))
			nfs_mount_data_version = 1;
		else if (kernel_version < MAKE_VERSION(2, 2, 18))
			nfs_mount_data_version = 3;
		else if (kernel_version < MAKE_VERSION(2, 3, 0))
			nfs_mount_data_version = 4;
		else if (kernel_version < MAKE_VERSION(2, 3, 99))
			nfs_mount_data_version = 3;
		else if (kernel_version < MAKE_VERSION(2, 6, 3))
			nfs_mount_data_version = 4;
		else
			nfs_mount_data_version = 6;
	}
	if (nfs_mount_data_version > NFS_MOUNT_VERSION)
		nfs_mount_data_version = NFS_MOUNT_VERSION;
}

/* Try to build a canonical options string.  */
static char * fix_opts_string (int flags, const char *extra_opts) {
	const struct opt_map *om;
	char *new_opts;

	new_opts = xstrdup((flags & MS_RDONLY) ? "ro" : "rw");
	if (flags & MS_USER) {
		/* record who mounted this so they can unmount */
		struct passwd *pw = getpwuid(getuid());
		if(pw)
			new_opts = xstrconcat3(new_opts, ",user=", pw->pw_name);
	}
	if (flags & MS_USERS)
		new_opts = xstrconcat3(new_opts, ",users", "");
	
	for (om = opt_map; om->opt != NULL; om++) {
		if (om->skip)
			continue;
		if (om->inv || !om->mask || (flags & om->mask) != om->mask)
			continue;
		new_opts = xstrconcat3(new_opts, ",", om->opt);
		flags &= ~om->mask;
	}
	if (extra_opts && *extra_opts) {
		new_opts = xstrconcat3(new_opts, ",", extra_opts);
	}
	return new_opts;
}

static int add_mtab(char *spec, char *mount_point, char *fstype,
			int flags, char *opts, int freq, int pass)
{
	struct mntent ment;
	FILE *mtab;
	int result = EX_FILEIO;

	ment.mnt_fsname = spec;
	ment.mnt_dir = mount_point;
	ment.mnt_type = fstype;
	ment.mnt_opts = fix_opts_string(flags, opts);
	ment.mnt_freq = freq;
	ment.mnt_passno = pass;

	if (flags & MS_REMOUNT) {
		update_mtab(ment.mnt_dir, &ment);
		return 0;
	}

	lock_mtab();

	if ((mtab = setmntent(MOUNTED, "a+")) == NULL) {
		unlock_mtab();
		nfs_error(_("Can't open mtab: %s"),
				strerror(errno));
		goto fail_unlock;
	}

	if (addmntent(mtab, &ment) == 1) {
		nfs_error(_("Can't write mount entry to mtab: %s"),
				strerror(errno));
		goto fail_close;
	}

	if (fchmod(fileno(mtab), 0644) == -1) {
		nfs_error(_("Can't set permissions on mtab: %s"),
				strerror(errno));
		goto fail_close;
	}

	result = 0;

fail_close:
	endmntent(mtab);
fail_unlock:
	unlock_mtab();

	return result;
}

int do_mount_syscall(char *spec, char *node, char *type, int flags, void *data)
{
	return mount(spec, node, type, flags, data);
}

void mount_usage()
{
	printf("usage: %s remotetarget dir [-rvVwfnh] [-o nfsoptions]\n",
		progname);
	printf("options:\n");
	printf("\t-r\t\tMount file system readonly\n");
	printf("\t-v\t\tVerbose\n");
	printf("\t-V\t\tPrint version\n");
	printf("\t-w\t\tMount file system read-write\n");
	printf("\t-f\t\tFake mount, do not actually mount\n");
	printf("\t-n\t\tDo not update /etc/mtab\n");
	printf("\t-s\t\tTolerate sloppy mount options rather than failing.\n");
	printf("\t-h\t\tPrint this help\n");
	printf("\tnfsoptions\tRefer to mount.nfs(8) or nfs(5)\n\n");
}

static inline void
parse_opt(const char *opt, int *mask, char *extra_opts, int len) {
	const struct opt_map *om;

	for (om = opt_map; om->opt != NULL; om++) {
		if (!strcmp (opt, om->opt)) {
			if (om->inv)
				*mask &= ~om->mask;
			else
				*mask |= om->mask;
			return;
		}
	}

	len -= strlen(extra_opts);

	if (*extra_opts && --len > 0)
		strcat(extra_opts, ",");

	if ((len -= strlen(opt)) > 0)
		strcat(extra_opts, opt);
}

/* Take -o options list and compute 4th and 5th args to mount(2).  flags
   gets the standard options (indicated by bits) and extra_opts all the rest */
static void parse_opts (const char *options, int *flags, char **extra_opts)
{
	if (options != NULL) {
		char *opts = xstrdup(options);
		char *opt, *p;
		int len = strlen(opts) + 1;		/* include room for a null */
		int open_quote = 0;

		*extra_opts = xmalloc(len);
		**extra_opts = '\0';

		for (p=opts, opt=NULL; p && *p; p++) {
			if (!opt)
				opt = p;		/* begin of the option item */
			if (*p == '"')
				open_quote ^= 1;	/* reverse the status */
			if (open_quote)
				continue;		/* still in a quoted block */
			if (*p == ',')
				*p = '\0';		/* terminate the option item */
			/* end of option item or last item */
			if (*p == '\0' || *(p+1) == '\0') {
				parse_opt(opt, flags, *extra_opts, len);
				opt = NULL;
			}
		}
		free(opts);
	}
}

static int chk_mountpoint(char *mount_point)
{
	struct stat sb;

	if (stat(mount_point, &sb) < 0){
		mount_error(NULL, mount_point, errno);
		return 1;
	}
	if (S_ISDIR(sb.st_mode) == 0){
		mount_error(NULL, mount_point, ENOTDIR);
		return 1;
	}
	if (access(mount_point, X_OK) < 0) {
		mount_error(NULL, mount_point, errno);
		return 1;
	}

	return 0;
}

extern u_short getport(
	struct sockaddr_in *saddr,
	u_long prog,
	u_long vers,
	u_int prot);

static int probe_statd()
{
	struct sockaddr_in addr;
	u_short port;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	port = getport(&addr, 100024, 1, IPPROTO_UDP);

	if (port == 0)
		return 0;
	addr.sin_port = htons(port);

	if (clnt_ping(&addr, 100024, 1, IPPROTO_UDP, NULL) <= 0)
		return 0;

	return 1;
}

static int start_statd()
{
	/* If /var/run/rpc.statd.pid exists and is non-empty,
	 * assume statd already running.
	 * If START_STATD not defined, or defined to a non-existent file,
	 * don't bother,
	 * else run that file (typically a shell script)
	 */
	struct stat stb;

	if (probe_statd())
		return 1;
#ifdef START_STATD
	if (stat(START_STATD, &stb) ==0 &&
	    S_ISREG(stb.st_mode) &&
	    (stb.st_mode & S_IXUSR)) {
		system(START_STATD);
		if (probe_statd())
			return 1;
	}
#endif
	return 0;
}

int main(int argc, char *argv[])
{
	int c, flags = 0, mnt_err = 1, fake = 0;
	char *spec, *mount_point, *fs_type = "nfs";
	char *extra_opts = NULL, *mount_opts = NULL;
	uid_t uid = getuid();

	progname = basename(argv[0]);

	discover_nfs_mount_data_version();

	if(!strncmp(progname, "umount", strlen("umount"))) {
		if(argc < 2) {
			umount_usage();
			exit(1);
		}
		exit(nfsumount(argc, argv));
	}

	if(argv[1] && argv[1][0] == '-') {
		if(argv[1][1] == 'V')
			printf("%s ("PACKAGE_STRING")\n", progname);
		else
			mount_usage();
		return 0;
	}

	if ((argc < 3)) {
		mount_usage();
		exit(1);
	}

	spec = argv[1];
	mount_point = argv[2];

	argv[2] = argv[0]; /* so that getopt error messages are correct */
	while ((c = getopt_long(argc - 2, argv + 2, "rvVwfno:hs",
				longopts, NULL)) != -1) {
		switch (c) {
		case 'r':
			flags |= MS_RDONLY;
			break;
		case 'v':
			++verbose;
			break;
		case 'V':
			printf("%s: ("PACKAGE_STRING")\n", progname);
			return 0;
		case 'w':
			flags &= ~MS_RDONLY;
			break;
		case 'f':
			++fake;
			break;
		case 'n':
			++nomtab;
			break;
		case 'o':              /* specify mount options */
			if (mount_opts)
				mount_opts = xstrconcat3(mount_opts, ",", optarg);
			else
				mount_opts = xstrdup(optarg);
			break;
		case 's':
			++sloppy;
			break;
		case 'h':
		default:
			mount_usage();
			exit(1);
		}
	}
	if (optind != argc-2) {
		/* Extra non-option words at the end... */
		mount_usage();
		exit(1);
	}

	if (strcmp(progname, "mount.nfs4") == 0)
		fs_type = "nfs4";

	/*
	 * If a non-root user is attempting to mount, make sure the
	 * user's requested options match the options specified in
	 * /etc/fstab; otherwise, don't allow the mount.
	 */
	if (uid != 0) {
		struct mntentchn *mc;

		if ((mc = getfsfile(mount_point)) == NULL ||
		    strcmp(mc->m.mnt_fsname, spec) != 0 ||
		    strcmp(mc->m.mnt_type, fs_type) != 0) {
			fprintf(stderr, "%s: permission denied: no match for %s "
				"found in /etc/fstab\n", progname, mount_point);
			exit(1);
		}

		/*
		 * 'mount' munges the options from fstab before passing them
		 * to us, so it is non-trivial to test that we have the correct
		 * set of options and we don't want to trust what the user
		 * gave us, so just take whatever is in /etc/fstab.
		 */
		mount_opts = strdup(mc->m.mnt_opts);
	}

	mount_point = canonicalize(mount_point);
	if (mount_point == NULL ||
	    mount_point[0] != '/') {
		fprintf(stderr, "%s: unknown mount point %s\n",
			progname, mount_point ? : "");
		exit(1);
	}
	
	parse_opts(mount_opts, &flags, &extra_opts);

	if (uid != 0) {
	    if (! (flags & (MS_USERS | MS_USER))) {
		    fprintf(stderr, "%s: permission denied\n", progname);
		    exit(1);
	    }
	}

	if (chk_mountpoint(mount_point))
		exit(EX_FAIL);

	if (strcmp(fs_type, "nfs4") == 0)
		mnt_err = nfs4mount(spec, mount_point, &flags, &extra_opts, &mount_opts, 0);
	else {
		int need_statd = 0;
		mnt_err = nfsmount(spec, mount_point, &flags,
				   &extra_opts, &mount_opts,
				   0, &need_statd);
		if (!mnt_err && !fake && need_statd) {
			if (!start_statd()) {
				fprintf(stderr,
					"%s: rpc.statd is not running but is "
					"required for remote locking\n"
					"   Either use \"-o nolocks\" to keep "
					"locks local, or start statd.\n",
					progname);
				exit(1);
			}
		}
	}

	if (mnt_err)
		exit(EX_FAIL);

	if (!fake) {
		mnt_err = do_mount_syscall(spec, mount_point, fs_type,
					   flags & ~(MS_USER|MS_USERS) ,
					   mount_opts);

		if (mnt_err) {
			mount_error(spec, mount_point, errno);
			exit(EX_FAIL);
		}
	}

	if (!nomtab)
		mnt_err = add_mtab(spec, mount_point, fs_type, flags, extra_opts,
				0, 0 /* these are always zero for NFS */ );

	exit(mnt_err);
}

