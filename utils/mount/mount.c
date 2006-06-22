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
#include <getopt.h>
#include <mntent.h>

#include "fstab.h"
#include "xcommon.h"
#include "mount_constants.h"
#include "nfs_paths.h"

#include "nfs_mount.h"
#include "nfs4_mount.h"
#include "nfsumount.h"
#include "mount.h"

char *progname;
int nomtab;
int verbose;
int mounttype;

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
  { "nfsvers", 1, 0, 't' },
  { "bind", 0, 0, 128 },
  { "replace", 0, 0, 129 },
  { "after", 0, 0, 130 },
  { "before", 0, 0, 131 },
  { "over", 0, 0, 132 },
  { "move", 0, 0, 133 },
  { "rbind", 0, 0, 135 },
  { NULL, 0, 0, 0 }
};

/* Map from -o and fstab option strings to the flag argument to mount(2).  */
struct opt_map {
  const char *opt;              /* option name */
  int  skip;                    /* skip in mtab option string */
  int  inv;                     /* true if flag value should be inverted */
  int  mask;                    /* flag mask value */
};

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

/* Try to build a canonical options string.  */
static char * fix_opts_string (int flags, const char *extra_opts) {
	const struct opt_map *om;
	char *new_opts;

	new_opts = xstrdup((flags & MS_RDONLY) ? "ro" : "rw");
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


int add_mtab(char *fsname, char *mount_point, char *fstype, int flags, char *opts, int freq, int passno)
{
	struct mntent ment;
	int fd;
	FILE *mtab;

	ment.mnt_fsname = fsname;
	ment.mnt_dir = mount_point;
	ment.mnt_type = fstype;
	ment.mnt_opts = fix_opts_string(flags, opts);
	ment.mnt_freq = 0;
	ment.mnt_passno= 0;

	if ((fd = open(MOUNTED"~", O_RDWR|O_CREAT|O_EXCL, 0600)) == -1)	{
		fprintf(stderr, "Can't get "MOUNTED"~ lock file");
		return 1;
	}
        close(fd);

        if ((mtab = setmntent(MOUNTED, "a+")) == NULL) {
		fprintf(stderr, "Can't open " MOUNTED);
		return 1;
	}

        if (addmntent(mtab, &ment) == 1) {
		fprintf(stderr, "Can't write mount entry");
		return 1;
	}

        if (fchmod(fileno(mtab), 0644) == -1) {
		fprintf(stderr, "Can't set perms on " MOUNTED);
		return 1;
	}

	endmntent(mtab);

	if (unlink(MOUNTED"~") == -1) {
		fprintf(stderr, "Can't remove "MOUNTED"~");
		return 1;
	}

	return 0;
}

int do_mount_syscall(char *spec, char *node, char *type, int flags, void *data)
{
	return mount(spec, node, type, flags, data);
}

void mount_usage()
{
	printf("usage: %s remotetarget dir [-rvVwfnh] [-t version] [-o nfsoptions]\n", progname);
	printf("options:\n\t-r\t\tMount file system readonly\n");
	printf("\t-v\t\tVerbose\n");
	printf("\t-V\t\tPrint version\n");
	printf("\t-w\t\tMount file system read-write\n");
	printf("\t-f\t\tFake mount, don't actually mount\n");
	printf("\t-n\t\tDo not update /etc/mtab\n");
	printf("\t-h\t\tPrint this help\n");
	printf("\tversion\t\tnfs4 - NFS version 4, nfs - older NFS version supported\n");
	printf("\tnfsoptions\tRefer mount.nfs(8) or nfs(5)\n\n");
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
		char *opt;
		int len = strlen(opts) + 20;

		*extra_opts = xmalloc(len);
		**extra_opts = '\0';

		for (opt = strtok(opts, ","); opt; opt = strtok(NULL, ","))
			parse_opt(opt, flags, *extra_opts, len);

		free(opts);
	}

}

static void mount_error(char *node)
{
	switch(errno) {
		case ENOTDIR:
			printf("%s: mount point %s is not a directory\n", progname, node);
			break;
		case EBUSY:
			printf("%s: %s is already mounted or busy\n", progname, node);
			break;
		case ENOENT:
			printf("%s: mount point %s does not exist\n", progname, node);
			break;
		default:
			printf("%s: %s\n", progname, strerror(errno));
	}
}

int main(int argc, char *argv[])
{
	int c, flags = 0, nfs_mount_vers = 0, mnt_err = 1, fake = 0;
	char *spec, *mount_point, *extra_opts = NULL;
	char *mount_opts = NULL, *p;

	progname = argv[0];
	if ((p = strrchr(progname, '/')) != NULL)
		progname = p+1;

	if (getuid() != 0) {
		printf("%s: only root can do that.\n", progname);
		exit(1);
	}

	if(!strncmp(progname, "umount", strlen("umount"))) {
		if(argc < 2) {
			umount_usage();
			exit(1);
		}
		return(nfsumount(argc, argv));
	}

	if ((argc < 2)) {
		mount_usage();
		exit(1);
	}

	if(argv[1][0] == '-') {
		if(argv[1][1] == 'V')
			printf("%s ("PACKAGE_STRING")\n", progname);
		else
			mount_usage();
		return 0;
	}

	while ((c = getopt_long (argc - 2, argv + 2, "rt:vVwfno:h",
				longopts, NULL)) != -1) {
		switch (c) {
		case 'r':
			flags |= MS_RDONLY;
			break;
		case 't':
			nfs_mount_vers = (strncmp(optarg, "nfs4", 4)) ? 0 : 4;
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
		case 128: /* bind */
			mounttype = MS_BIND;
			break;
		case 129: /* replace */
			mounttype = MS_REPLACE;
			break;
		case 130: /* after */
			mounttype = MS_AFTER;
			break;
		case 131: /* before */
			mounttype = MS_BEFORE;
			break;
		case 132: /* over */
			mounttype = MS_OVER;
			break;
		case 133: /* move */
			mounttype = MS_MOVE;
			break;
		case 135: /* rbind */
			mounttype = MS_BIND | MS_REC;
			break;
		case 'h':
		default:
			mount_usage();
			exit(1);
		}
	}

	spec = argv[1];
	mount_point = canonicalize(argv[2]);
	
	parse_opts(mount_opts, &flags, &extra_opts);

	if (!strcmp(progname, "mount.nfs4") || nfs_mount_vers == 4) {
		nfs_mount_vers = 4;
		mnt_err = nfs4mount(spec, mount_point, &flags, &extra_opts, &mount_opts, 0);
	}
	else {
		if (!strcmp(progname, "mount.nfs")) {
			mnt_err = nfsmount(spec, mount_point, &flags,
					&extra_opts, &mount_opts, &nfs_mount_vers, 0);
		}
	}

	if (!mnt_err && !fake) {
		mnt_err = do_mount_syscall(spec, mount_point, nfs_mount_vers == 4 ? "nfs4" : "nfs", flags, mount_opts);
		
		if(mnt_err) {
			mount_error(mount_point);
			exit(-1);
		}

		if(!nomtab)
			add_mtab(spec, mount_point, nfs_mount_vers == 4 ? "nfs4" : "nfs",
				 flags, extra_opts, 0, 0);
	}

	return 0;
}

