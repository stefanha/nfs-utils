/*
 * stropts.c -- NFS mount using C string to pass options to kernel
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
 */

#include <ctype.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/mount.h>

#include "xcommon.h"
#include "mount.h"
#include "nls.h"
#include "nfs_mount.h"
#include "mount_constants.h"
#include "stropts.h"
#include "error.h"
#include "network.h"

#ifdef HAVE_RPCSVC_NFS_PROT_H
#include <rpcsvc/nfs_prot.h>
#else
#include <linux/nfs.h>
#define nfsstat nfs_stat
#endif

#ifndef NFS_PORT
#define NFS_PORT 2049
#endif

#ifndef NFS_MAXHOSTNAME
#define NFS_MAXHOSTNAME		(255)
#endif

#ifndef NFS_MAXPATHNAME
#define NFS_MAXPATHNAME		(1024)
#endif

extern int nfs_mount_data_version;
extern char *progname;
extern int verbose;

static int retry_opt = 10000;		/* 10,000 minutes ~= 1 week */
static int bg_opt = 0;
static int addr_opt = 0;
static int ca_opt = 0;

static int parse_devname(const char *spec, char **hostname)
{
	int ret = 0;
	char *dev, *pathname, *s;

	dev = xstrdup(spec);

	if (!(pathname = strchr(dev, ':'))) {
		nfs_error(_("%s: remote share not in 'host:dir' format"),
				progname);
		goto out;
	}
	*pathname = '\0';
	pathname++;

	/*
	 * We don't need a copy of the pathname, but let's
	 * sanity check it anyway.
	 */
	if (strlen(pathname) > NFS_MAXPATHNAME) {
		nfs_error(_("%s: export pathname is too long"),
				progname);
		goto out;
	}

	/*
	 * Ignore all but first hostname in replicated mounts
	 * until they can be fully supported. (mack@sgi.com)
	 */
	if ((s = strchr(dev, ','))) {
		*s = '\0';
		nfs_error(_("%s: warning: multiple hostnames not supported"),
				progname);
		nfs_error(_("%s: ignoring hostnames that follow the first one"),
				progname);
	}
	*hostname = xstrdup(dev);
	if (strlen(*hostname) > NFS_MAXHOSTNAME) {
		nfs_error(_("%s: server hostname is too long"),
				progname);
		free(*hostname);
		goto out;
	}

	ret = 1;

out:
	free(dev);
	return ret;
}

static int fill_ipv4_sockaddr(const char *hostname, struct sockaddr_in *addr)
{
	struct hostent *hp;
	addr->sin_family = AF_INET;

	if (inet_aton(hostname, &addr->sin_addr))
		return 1;
	if ((hp = gethostbyname(hostname)) == NULL) {
		nfs_error(_("%s: can't get address for %s\n"),
				progname, hostname);
		return 0;
	}
	if (hp->h_length > sizeof(struct in_addr)) {
		nfs_error(_("%s: got bad hp->h_length"), progname);
		hp->h_length = sizeof(struct in_addr);
	}
	memcpy(&addr->sin_addr, hp->h_addr, hp->h_length);
	return 1;
}

/*
 * XXX: This should really use the technique neil recently added
 * to get the address off the local end of a socket connected to
 * the server -- to get the right address to use on multi-homed
 * clients
 */
static int get_my_ipv4addr(char *ip_addr, int len)
{
	char myname[1024];
	struct sockaddr_in myaddr;

	if (gethostname(myname, sizeof(myname))) {
		nfs_error(_("%s: can't determine client address\n"),
				progname);
		return 0;
	}
	if (!fill_ipv4_sockaddr(myname, &myaddr))
		return 0;

	snprintf(ip_addr, len, "%s", inet_ntoa(myaddr.sin_addr));
	ip_addr[len - 1] = '\0';

	return 1;
}

/*
 * Walk through our mount options string, and indicate the presence
 * of 'bg', 'retry=', 'addr=', and 'clientaddr='.
 */
static void extract_interesting_options(char *opts)
{
	char *opt, *opteq;
	int val;

	opts = xstrdup(opts);

	for (opt = strtok(opts, ","); opt; opt = strtok(NULL, ",")) {
		if ((opteq = strchr(opt, '='))) {
			val = atoi(opteq + 1);
			*opteq = '\0';
			if (strcmp(opt, "bg") == 0)
				bg_opt++;
			else if (strcmp(opt, "retry") == 0)
				retry_opt = val;
			else if (strcmp(opt, "addr") == 0)
				addr_opt++;
			else if (strcmp(opt, "clientaddr") == 0)
				ca_opt++;
		} else {
			if (strcmp(opt, "bg") == 0)
				bg_opt++;
		}
	}

	free(opts);
}

/*
 * Append the 'addr=' option to the options string.  The server
 * address is added to /etc/mtab for use when unmounting.
 *
 * Returns 1 if 'addr=' option created successfully;
 * otherwise zero.
 */
static int append_addr_opt(const char *spec, char **extra_opts)
{
	static char new_opts[1024];
	char *hostname, *s, *old_opts;
	struct sockaddr_in addr;
	int err;

	if (!parse_devname(spec, &hostname))
		return 0;

	err = fill_ipv4_sockaddr(hostname, &addr);
	free(hostname);
	if (!err)
		return 0;

	s = inet_ntoa(addr.sin_addr);
	old_opts = *extra_opts;
	if (!old_opts)
		old_opts = "";
	if (strlen(old_opts) + strlen(s) + 10 >= sizeof(new_opts)) {
		nfs_error(_("%s: excessively long option argument\n"),
				progname);
		return 0;
	}
	snprintf(new_opts, sizeof(new_opts), "%s%saddr=%s",
		 old_opts, *old_opts ? "," : "", s);
	*extra_opts = xstrdup(new_opts);

	return 1;
}

/*
 * Append the 'clientaddr=' option to the options string.
 *
 * Returns 1 if 'clientaddr=' option created successfully;
 * otherwise zero.
 */
static int append_clientaddr_opt(const char *spec, char **extra_opts)
{
	static char new_opts[1024], cbuf[1024];
	static char ip_addr[16] = "127.0.0.1";

	if (!get_my_ipv4addr(ip_addr, sizeof(ip_addr)))
		return 0;

	/* Ensure we have enough padding for the following strcat()s */
	if (strlen(*extra_opts) + strlen(ip_addr) + 10 >= sizeof(new_opts)) {
		nfs_error(_("%s: excessively long option argument"),
				progname);
		return 0;
	}

	strcat(new_opts, *extra_opts);

	snprintf(cbuf, sizeof(cbuf) - 1, "%sclientaddr=%s",
			*extra_opts ? "," : "", ip_addr);
	strcat(new_opts, cbuf);

	*extra_opts = xstrdup(new_opts);

	return 1;
}

/*
 * nfsmount_s - Mount an NFSv2 or v3 file system using C string options
 *
 * @spec:	C string hostname:path specifying remoteshare to mount
 * @node:	C string pathname of local mounted on directory
 * @flags:	MS_ style flags
 * @extra_opts:	pointer to C string containing fs-specific mount options
 *		(possibly also a return argument)
 * @fake:	flag indicating whether to carry out the whole operation
 * @bg:		one if this is a backgrounded mount attempt
 *
 * XXX: need to handle bg, fg, and retry options.
 */
int nfsmount_s(const char *spec, const char *node, int flags,
		char **extra_opts, int fake, int bg)
{
	int retval = EX_FAIL;

	extract_interesting_options(*extra_opts);

	if (!bg && addr_opt) {
		nfs_error(_("%s: Illegal option: 'addr='"), progname);
		goto fail;
	}

	if (!append_addr_opt(spec, extra_opts))
		goto fail;

	if (verbose)
		printf(_("%s: text-based options: '%s'\n"),
			progname, *extra_opts);

	if (!fake) {
		if (mount(spec, node, "nfs",
				flags & ~(MS_USER|MS_USERS), *extra_opts)) {
			mount_error(spec, node, errno);
			goto fail;
		}
	}

	return 0;

fail:
	return retval;
}

/*
 * nfs4mount_s - Mount an NFSv4 file system using C string options
 *
 * @spec:	C string hostname:path specifying remoteshare to mount
 * @node:	C string pathname of local mounted on directory
 * @flags:	MS_ style flags
 * @extra_opts:	pointer to C string containing fs-specific mount options
 *		(possibly also a return argument)
 * @fake:	flag indicating whether to carry out the whole operation
 * @child:	one if this is a backgrounded mount
 *
 * XXX: need to handle bg, fg, and retry options.
 *
 */
int nfs4mount_s(const char *spec, const char *node, int flags,
		char **extra_opts, int fake, int child)
{
	int retval = EX_FAIL;

	extract_interesting_options(*extra_opts);

	if (addr_opt) {
		nfs_error(_("%s: Illegal option: 'addr='"), progname);
		goto fail;
	}

	if (ca_opt) {
		nfs_error(_("%s: Illegal option: 'clientaddr='"), progname);
		goto fail;
	}

	if (!append_addr_opt(spec, extra_opts))
		goto fail;

	if (!append_clientaddr_opt(spec, extra_opts))
		goto fail;

	if (verbose)
		printf(_("%s: text-based options: '%s'\n"),
			progname, *extra_opts);

	if (!fake) {
		if (mount(spec, node, "nfs4",
				flags & ~(MS_USER|MS_USERS), *extra_opts)) {
			mount_error(spec, node, errno);
			goto fail;
		}
	}

	return 0;

fail:
	return retval;
}
