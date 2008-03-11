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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

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
#include "parse_opt.h"

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
 * Append the 'addr=' option to the options string to pass a resolved
 * server address to the kernel.  After a successful mount, this address
 * is also added to /etc/mtab for use when unmounting.
 *
 * If 'addr=' is already present, we strip it out.  This prevents users
 * from setting a bogus 'addr=' option themselves, and also allows bg
 * retries to recompute the server's address, in case it has changed.
 *
 * Returns 1 if 'addr=' option appended successfully;
 * otherwise zero.
 */
static int append_addr_option(struct sockaddr_in *saddr,
			   struct mount_options *options)
{
	char new_option[24];

	po_remove_all(options, "addr");

	snprintf(new_option, sizeof(new_option) - 1,
			"addr=%s", inet_ntoa(saddr->sin_addr));

	if (po_append(options, new_option) == PO_SUCCEEDED)
		return 1;
	return 0;
}

/*
 * Called to discover our address and append an appropriate 'clientaddr='
 * option to the options string.
 *
 * Returns 1 if 'clientaddr=' option created successfully or if
 * 'clientaddr=' option is already present; otherwise zero.
 */
static int append_clientaddr_option(struct sockaddr_in *saddr,
				    struct mount_options *options)
{
	struct sockaddr_in my_addr;
	char new_option[32];

	if (po_contains(options, "clientaddr") == PO_SUCCEEDED)
		return 1;

	if (!get_client_address(saddr, &my_addr))
		return 0;

	snprintf(new_option, sizeof(new_option) - 1,
			"clientaddr=%s", inet_ntoa(my_addr.sin_addr));

	if (po_append(options, new_option) == PO_SUCCEEDED)
		return 1;
	return 0;
}

/*
 * Resolve the 'mounthost=' hostname and append a new option using
 * the resulting IPv4 address.
 */
static int fix_mounthost_option(struct mount_options *options)
{
	struct sockaddr_in maddr;
	char *mounthost, new_option[32];

	mounthost = po_get(options, "mounthost");
	if (!mounthost)
		return 1;

	if (!fill_ipv4_sockaddr(mounthost, &maddr))
		return 0;

	snprintf(new_option, sizeof(new_option) - 1,
			"mountaddr=%s", inet_ntoa(maddr.sin_addr));

	if (po_append(options, new_option) == PO_SUCCEEDED)
		return 1;
	return 0;
}

/*
 * Set up mandatory mount options.
 *
 * Returns 1 if successful; otherwise zero.
 */
static int set_mandatory_options(const char *type,
				 struct sockaddr_in *saddr,
				 struct mount_options *options)
{
	if (!append_addr_option(saddr, options))
		return 0;

	if (strncmp(type, "nfs4", 4) == 0) {
		if (!append_clientaddr_option(saddr, options))
			return 0;
	} else {
		if (!fix_mounthost_option(options))
			return 0;
	}

	return 1;
}

/*
 * Distinguish between permanent and temporary errors.
 *
 * Returns 0 if the passed-in error is temporary, thus the
 * mount system call should be retried; returns one if the
 * passed-in error is permanent, thus the mount system call
 * should not be retried.
 */
static int is_permanent_error(int error)
{
	switch (error) {
	case EACCES:
	case ESTALE:
	case ETIMEDOUT:
	case ECONNREFUSED:
		return 0;	/* temporary */
	default:
		return 1;	/* permanent */
	}
}

/*
 * Reconstruct the mount option string based on a portmapper probe
 * of the server.  Returns one if the server's portmapper returned
 * something we can use, otherwise zero.
 *
 * To handle version and transport protocol fallback properly, we
 * need to parse some of the mount options in order to set up a
 * portmap probe.  Mount options that rewrite_mount_options()
 * doesn't recognize are left alone.
 *
 * Returns a new group of mount options if successful; otherwise
 * NULL is returned if some failure occurred.
 */
static struct mount_options *rewrite_mount_options(char *str)
{
	struct mount_options *options;
	char *option, new_option[64];
	clnt_addr_t mnt_server = { };
	clnt_addr_t nfs_server = { };
	int p;

	options = po_split(str);
	if (!options)
		return NULL;

	option = po_get(options, "addr");
	if (option) {
		nfs_server.saddr.sin_family = AF_INET;
		if (!inet_aton((const char *)option, &nfs_server.saddr.sin_addr))
			goto err;
	} else
		goto err;

	option = po_get(options, "mountaddr");
	if (option) {
		mnt_server.saddr.sin_family = AF_INET;
		if (!inet_aton((const char *)option, &mnt_server.saddr.sin_addr))
			goto err;
	} else
		memcpy(&mnt_server.saddr, &nfs_server.saddr,
				sizeof(mnt_server.saddr));

	option = po_get(options, "mountport");
	if (option)
		mnt_server.pmap.pm_port = atoi(option);
	mnt_server.pmap.pm_prog = MOUNTPROG;
	option = po_get(options, "mountvers");
	if (option)
		mnt_server.pmap.pm_vers = atoi(option);

	option = po_get(options, "port");
	if (option) {
		nfs_server.pmap.pm_port = atoi(option);
		po_remove_all(options, "port");
	}
	nfs_server.pmap.pm_prog = NFS_PROGRAM;

	option = po_get(options, "nfsvers");
	if (option) {
		nfs_server.pmap.pm_vers = atoi(option);
		po_remove_all(options, "nfsvers");
	}
	option = po_get(options, "vers");
	if (option) {
		nfs_server.pmap.pm_vers = atoi(option);
		po_remove_all(options, "vers");
	}
	option = po_get(options, "proto");
	if (option) {
		if (strcmp(option, "tcp") == 0) {
			nfs_server.pmap.pm_prot = IPPROTO_TCP;
			po_remove_all(options, "proto");
		}
		if (strcmp(option, "udp") == 0) {
			nfs_server.pmap.pm_prot = IPPROTO_UDP;
			po_remove_all(options, "proto");
		}
	}
	p = po_rightmost(options, "tcp", "udp");
	switch (p) {
	case PO_KEY2_RIGHTMOST:
		nfs_server.pmap.pm_prot = IPPROTO_UDP;
		break;
	case PO_KEY1_RIGHTMOST:
		nfs_server.pmap.pm_prot = IPPROTO_TCP;
		break;
	}
	po_remove_all(options, "tcp");
	po_remove_all(options, "udp");

	if (!probe_bothports(&mnt_server, &nfs_server)) {
		rpc_mount_errors("rpcbind", 0, 0);
		goto err;
	}

	snprintf(new_option, sizeof(new_option) - 1,
		 "nfsvers=%lu", nfs_server.pmap.pm_vers);
	if (po_append(options, new_option) == PO_FAILED)
		goto err;

	if (nfs_server.pmap.pm_prot == IPPROTO_TCP)
		snprintf(new_option, sizeof(new_option) - 1,
			 "proto=tcp");
	else
		snprintf(new_option, sizeof(new_option) - 1,
			 "proto=udp");
	if (po_append(options, new_option) == PO_FAILED)
		goto err;

	if (nfs_server.pmap.pm_port != NFS_PORT) {
		snprintf(new_option, sizeof(new_option) - 1,
			 "port=%lu", nfs_server.pmap.pm_port);
		if (po_append(options, new_option) == PO_FAILED)
			goto err;

	}

	return options;

err:
	po_destroy(options);
	return NULL;
}

/*
 * Retry an NFS mount that failed because the requested service isn't
 * available on the server.
 *
 * Returns 1 if successful.  Otherwise, returns zero.
 * "errno" is set to reflect the individual error.
 *
 * Side effect: If the retry is successful, both 'options' and
 * 'extra_opts' are updated to reflect the mount options that worked.
 * If the retry fails, 'options' and 'extra_opts' are left unchanged.
 */
static int retry_nfsmount(const char *spec, const char *node,
			int flags, struct mount_options *options,
			int fake, char **extra_opts)
{
	struct mount_options *retry_options;
	char *retry_str = NULL;

	retry_options = rewrite_mount_options(*extra_opts);
	if (!retry_options) {
		errno = EIO;
		return 0;
	}

	if (po_join(retry_options, &retry_str) == PO_FAILED) {
		po_destroy(retry_options);
		errno = EIO;
		return 0;
	}

	if (verbose)
		printf(_("%s: text-based options (retry): '%s'\n"),
			progname, retry_str);

	if (!mount(spec, node, "nfs",
				flags & ~(MS_USER|MS_USERS), retry_str)) {
		free(*extra_opts);
		*extra_opts = retry_str;
		po_replace(options, retry_options);
		return 1;
	}

	po_destroy(retry_options);
	free(retry_str);
	return 0;
}

/*
 * Attempt an NFSv2/3 mount via a mount(2) system call.  If the kernel
 * claims the requested service isn't supported on the server, probe
 * the server to see what's supported, rewrite the mount options,
 * and retry the request.
 *
 * Returns 1 if successful.  Otherwise, returns zero.
 * "errno" is set to reflect the individual error.
 *
 * Side effect: If the retry is successful, both 'options' and
 * 'extra_opts' are updated to reflect the mount options that worked.
 * If the retry fails, 'options' and 'extra_opts' are left unchanged.
 */
static int try_nfs23mount(const char *spec, const char *node,
			  int flags, struct mount_options *options,
			  int fake, char **extra_opts)
{
	if (po_join(options, extra_opts) == PO_FAILED) {
		errno = EIO;
		return 0;
	}

	if (verbose)
		printf(_("%s: text-based options: '%s'\n"),
			progname, *extra_opts);

	if (fake)
		return 1;

	if (!mount(spec, node, "nfs",
				flags & ~(MS_USER|MS_USERS), *extra_opts))
		return 1;

	/*
	 * The kernel returns EOPNOTSUPP if the RPC bind failed,
	 * and EPROTONOSUPPORT if the version isn't supported.
	 */
	if (errno != EOPNOTSUPP && errno != EPROTONOSUPPORT)
		return 0;

	return retry_nfsmount(spec, node, flags, options, fake, extra_opts);
}

/*
 * Attempt an NFS v4 mount via a mount(2) system call.
 *
 * Returns 1 if successful.  Otherwise, returns zero.
 * "errno" is set to reflect the individual error.
 */
static int try_nfs4mount(const char *spec, const char *node,
			 int flags, struct mount_options *options,
			 int fake, char **extra_opts)
{
	if (po_join(options, extra_opts) == PO_FAILED) {
		errno = EIO;
		return 0;
	}

	if (verbose)
		printf(_("%s: text-based options: '%s'\n"),
			progname, *extra_opts);

	if (fake)
		return 1;

	if (!mount(spec, node, "nfs4",
				flags & ~(MS_USER|MS_USERS), *extra_opts))
		return 1;
	return 0;
}

/*
 * Try the mount(2) system call.
 *
 * Returns 1 if successful.  Otherwise, returns zero.
 * "errno" is set to reflect the individual error.
 */
static int try_mount(const char *spec, const char *node, const char *type,
		     int flags, struct mount_options *options, int fake,
		     char **extra_opts)
{
	if (strncmp(type, "nfs4", 4) == 0)
		return try_nfs4mount(spec, node, flags,
					options, fake, extra_opts);
	else
		return try_nfs23mount(spec, node, flags,
					options, fake, extra_opts);
}

/*
 * Handle "foreground" NFS mounts.
 *
 * Retry the mount request for as long as the 'retry=' option says.
 *
 * Returns a valid mount command exit code.
 */
static int nfsmount_fg(const char *spec, const char *node,
		       const char *type, int flags,
		       struct mount_options *options, int fake,
		       char **extra_opts)
{
	unsigned int secs = 1;
	time_t timeout = time(NULL);
	char *retry;

	timeout += 60 * 2;		/* default: 2 minutes */
	retry = po_get(options, "retry");
	if (retry)
		timeout += 60 * atoi(retry);

	if (verbose)
		printf(_("%s: timeout set for %s"),
			progname, ctime(&timeout));

	for (;;) {
		if (try_mount(spec, node, type, flags,
					options, fake, extra_opts))
			return EX_SUCCESS;

		if (is_permanent_error(errno))
			break;

		if (time(NULL) > timeout) {
			errno = ETIMEDOUT;
			break;
		}

		if (errno != ETIMEDOUT) {
			if (sleep(secs))
				break;
			secs <<= 1;
			if (secs > 10)
				secs = 10;
		}
	};

	mount_error(spec, node, errno);
	return EX_FAIL;
}

/*
 * Handle "background" NFS mount [first try]
 *
 * Returns a valid mount command exit code.
 *
 * EX_BG should cause the caller to fork and invoke nfsmount_child.
 */
static int nfsmount_parent(const char *spec, const char *node,
			   const char *type, char *hostname, int flags,
			   struct mount_options *options,
			   int fake, char **extra_opts)
{
	if (try_mount(spec, node, type, flags, options,
					fake, extra_opts))
		return EX_SUCCESS;

	if (is_permanent_error(errno)) {
		mount_error(spec, node, errno);
		return EX_FAIL;
	}

	sys_mount_errors(hostname, errno, 1, 1);
	return EX_BG;
}

/*
 * Handle "background" NFS mount [retry daemon]
 *
 * Returns a valid mount command exit code: EX_SUCCESS if successful,
 * EX_FAIL if a failure occurred.  There's nothing to catch the
 * error return, though, so we use sys_mount_errors to log the
 * failure.
 */
static int nfsmount_child(const char *spec, const char *node,
			  const char *type, char *hostname, int flags,
			  struct mount_options *options,
			  int fake, char **extra_opts)
{
	unsigned int secs = 1;
	time_t timeout = time(NULL);
	char *retry;

	timeout += 60 * 10000;		/* default: 10,000 minutes */
	retry = po_get(options, "retry");
	if (retry)
		timeout += 60 * atoi(retry);

	for (;;) {
		if (sleep(secs))
			break;
		secs <<= 1;
		if (secs > 120)
			secs = 120;

		if (try_mount(spec, node, type, flags, options,
							fake, extra_opts))
			return EX_SUCCESS;

		if (is_permanent_error(errno))
			break;

		if (time(NULL) > timeout)
			break;

		sys_mount_errors(hostname, errno, 1, 1);
	};

	sys_mount_errors(hostname, errno, 1, 0);
	return EX_FAIL;
}

/*
 * Handle "background" NFS mount
 *
 * Returns a valid mount command exit code.
 */
static int nfsmount_bg(const char *spec, const char *node,
			  const char *type, char *hostname, int flags,
			  struct mount_options *options,
			  int fake, int child, char **extra_opts)
{
	if (!child)
		return nfsmount_parent(spec, node, type, hostname, flags,
					options, fake, extra_opts);
	else
		return nfsmount_child(spec, node, type, hostname, flags,
					options, fake, extra_opts);
}

/**
 * nfsmount_string - Mount an NFS file system using C string options
 * @spec: C string specifying remote share to mount ("hostname:path")
 * @node: C string pathname of local mounted-on directory
 * @type: C string that represents file system type ("nfs" or "nfs4")
 * @flags: MS_ style mount flags
 * @extra_opts:	pointer to C string containing fs-specific mount options
 *		(input and output argument)
 * @fake: flag indicating whether to carry out the whole operation
 * @child: one if this is a mount daemon (bg)
 */
int nfsmount_string(const char *spec, const char *node, const char *type,
		    int flags, char **extra_opts, int fake, int child)
{
	struct mount_options *options = NULL;
	struct sockaddr_in saddr;
	char *hostname;
	int retval = EX_FAIL;

	if (!parse_devname(spec, &hostname))
		return retval;
	if (!fill_ipv4_sockaddr(hostname, &saddr))
		goto fail;

	options = po_split(*extra_opts);
	if (!options) {
		nfs_error(_("%s: internal option parsing error"), progname);
		goto fail;
	}

	if (!set_mandatory_options(type, &saddr, options))
		goto out;

	if (po_rightmost(options, "bg", "fg") == PO_KEY1_RIGHTMOST)
		retval = nfsmount_bg(spec, node, type, hostname, flags,
					options, fake, child, extra_opts);
	else
		retval = nfsmount_fg(spec, node, type, flags, options,
							fake, extra_opts);

out:
	po_destroy(options);
fail:
	free(hostname);
	return retval;
}
