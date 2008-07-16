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

#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/mount.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "xcommon.h"
#include "mount.h"
#include "nls.h"
#include "mount_constants.h"
#include "stropts.h"
#include "error.h"
#include "network.h"
#include "parse_opt.h"
#include "version.h"
#include "parse_dev.h"

#ifndef NFS_PROGRAM
#define NFS_PROGRAM	(100003)
#endif

#ifndef NFS_PORT
#define NFS_PORT	(2049)
#endif

#ifndef NFS_MAXHOSTNAME
#define NFS_MAXHOSTNAME		(255)
#endif

#ifndef NFS_MAXPATHNAME
#define NFS_MAXPATHNAME		(1024)
#endif

#ifndef NFS_DEF_FG_TIMEOUT_MINUTES
#define NFS_DEF_FG_TIMEOUT_MINUTES	(2u)
#endif

#ifndef NFS_DEF_BG_TIMEOUT_MINUTES
#define NFS_DEF_BG_TIMEOUT_MINUTES	(10000u)
#endif

extern int nfs_mount_data_version;
extern char *progname;
extern int verbose;
extern int sloppy;

struct nfsmount_info {
	const char		*spec,		/* server:/path */
				*node,		/* mounted-on dir */
				*type;		/* "nfs" or "nfs4" */
	char			*hostname;	/* server's hostname */

	struct mount_options	*options;	/* parsed mount options */
	char			**extra_opts;	/* string for /etc/mtab */

	int			flags,		/* MS_ flags */
				fake,		/* actually do the mount? */
				child;		/* forked bg child? */

	sa_family_t		family;		/* supported address family */
};

/*
 * Obtain a retry timeout value based on the value of the "retry=" option.
 *
 * Returns a time_t timeout timestamp, in seconds.
 */
static time_t nfs_parse_retry_option(struct mount_options *options,
				     unsigned int timeout_minutes)
{
	char *retry_option, *endptr;

	retry_option = po_get(options, "retry");
	if (retry_option) {
		long tmp;

		errno = 0;
		tmp = strtol(retry_option, &endptr, 10);
		if (errno == 0 && endptr != retry_option && tmp >= 0)
			timeout_minutes = tmp;
		else if (verbose)
			nfs_error(_("%s: invalid retry timeout was specified; "
					"using default timeout"), progname);
	}

	return time(NULL) + (time_t)(timeout_minutes * 60);
}

/*
 * Convert the passed-in sockaddr-style address to presentation
 * format, then append an option of the form "keyword=address".
 *
 * Returns 1 if the option was appended successfully; otherwise zero.
 */
static int nfs_append_generic_address_option(const struct sockaddr *sap,
					     const socklen_t salen,
					     const char *keyword,
					     struct mount_options *options)
{
	char address[NI_MAXHOST];
	char new_option[512];

	if (!nfs_present_sockaddr(sap, salen, address, sizeof(address)))
		goto out_err;

	if (snprintf(new_option, sizeof(new_option), "%s=%s",
					keyword, address) >= sizeof(new_option))
		goto out_err;

	if (po_append(options, new_option) != PO_SUCCEEDED)
		goto out_err;

	return 1;

out_err:
	nfs_error(_("%s: failed to construct %s option"), progname, keyword);
	return 0;
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
static int nfs_append_addr_option(const struct sockaddr *sap,
				  socklen_t salen,
				  struct mount_options *options)
{
	po_remove_all(options, "addr");
	return nfs_append_generic_address_option(sap, salen, "addr", options);
}

/*
 * Called to discover our address and append an appropriate 'clientaddr='
 * option to the options string.
 *
 * Returns 1 if 'clientaddr=' option created successfully or if
 * 'clientaddr=' option is already present; otherwise zero.
 */
static int nfs_append_clientaddr_option(const struct sockaddr *sap,
					socklen_t salen,
					struct mount_options *options)
{
	struct sockaddr_storage dummy;
	struct sockaddr *my_addr = (struct sockaddr *)&dummy;
	socklen_t my_len = sizeof(dummy);

	if (po_contains(options, "clientaddr") == PO_FOUND)
		return 1;

	nfs_callback_address(sap, salen, my_addr, &my_len);

	return nfs_append_generic_address_option(my_addr, my_len,
							"clientaddr", options);
}

/*
 * Resolve the 'mounthost=' hostname and append a new option using
 * the resulting address.
 */
static int nfs_fix_mounthost_option(const sa_family_t family,
				    struct mount_options *options)
{
	struct sockaddr_storage dummy;
	struct sockaddr *sap = (struct sockaddr *)&dummy;
	socklen_t salen = sizeof(dummy);
	char *mounthost;

	mounthost = po_get(options, "mounthost");
	if (!mounthost)
		return 1;

	if (!nfs_name_to_address(mounthost, family, sap, &salen)) {
		nfs_error(_("%s: unable to determine mount server's address"),
				progname);
		return 0;
	}

	return nfs_append_generic_address_option(sap, salen,
							"mountaddr", options);
}

/*
 * Returns zero if the "lock" option is in effect, but statd
 * can't be started.  Otherwise, returns 1.
 */
static int nfs_verify_lock_option(struct mount_options *options)
{
	if (po_rightmost(options, "nolock", "lock") == PO_KEY1_RIGHTMOST)
		return 1;

	if (!start_statd()) {
		nfs_error(_("%s: rpc.statd is not running but is "
			    "required for remote locking."), progname);
		nfs_error(_("%s: Either use '-o nolock' to keep "
			    "locks local, or start statd."), progname);
		return 0;
	}

	return 1;
}

static int nfs_append_sloppy_option(struct mount_options *options)
{
	if (!sloppy || linux_version_code() < MAKE_VERSION(2, 6, 27))
		return 1;

	if (po_append(options, "sloppy") == PO_FAILED)
		return 0;
	return 1;
}

/*
 * Set up mandatory NFS mount options.
 *
 * Returns 1 if successful; otherwise zero.
 */
static int nfs_validate_options(struct nfsmount_info *mi)
{
	struct sockaddr_storage dummy;
	struct sockaddr *sap = (struct sockaddr *)&dummy;
	socklen_t salen = sizeof(dummy);

	if (!nfs_parse_devname(mi->spec, &mi->hostname, NULL))
		return 0;

	if (!nfs_name_to_address(mi->hostname, mi->family, sap, &salen))
		return 0;

	if (strncmp(mi->type, "nfs4", 4) == 0) {
		if (!nfs_append_clientaddr_option(sap, salen, mi->options))
			return 0;
	} else {
		if (!nfs_fix_mounthost_option(mi->family, mi->options))
			return 0;
		if (!mi->fake && !nfs_verify_lock_option(mi->options))
			return 0;
	}

	if (!nfs_append_sloppy_option(mi->options))
		return 0;

	return nfs_append_addr_option(sap, salen, mi->options);
}

/*
 * Distinguish between permanent and temporary errors.
 *
 * Returns 0 if the passed-in error is temporary, thus the
 * mount system call should be retried; returns one if the
 * passed-in error is permanent, thus the mount system call
 * should not be retried.
 */
static int nfs_is_permanent_error(int error)
{
	switch (error) {
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
 * portmap probe.  Mount options that nfs_rewrite_mount_options()
 * doesn't recognize are left alone.
 *
 * Returns a new group of mount options if successful; otherwise
 * NULL is returned if some failure occurred.
 */
static struct mount_options *nfs_rewrite_mount_options(char *str)
{
	struct mount_options *options;
	char *option, new_option[64];
	clnt_addr_t mnt_server = { };
	clnt_addr_t nfs_server = { };
	int p;

	options = po_split(str);
	if (!options) {
		errno = EFAULT;
		return NULL;
	}

	errno = EINVAL;
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
	option = po_get(options, "mountproto");
	if (option) {
		if (strcmp(option, "tcp") == 0) {
			mnt_server.pmap.pm_prot = IPPROTO_TCP;
			po_remove_all(options, "mountproto");
		}
		if (strcmp(option, "udp") == 0) {
			mnt_server.pmap.pm_prot = IPPROTO_UDP;
			po_remove_all(options, "mountproto");
		}
	}

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
		errno = ESPIPE;
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

	if (mnt_server.pmap.pm_prot == IPPROTO_TCP)
		snprintf(new_option, sizeof(new_option) - 1,
			 "mountproto=tcp");
	else
		snprintf(new_option, sizeof(new_option) - 1,
			 "mountproto=udp");
	if (po_append(options, new_option) == PO_FAILED)
		goto err;

	snprintf(new_option, sizeof(new_option) - 1,
		 "mountport=%lu", mnt_server.pmap.pm_port);
	if (po_append(options, new_option) == PO_FAILED)
		goto err;

	errno = 0;
	return options;

err:
	po_destroy(options);
	return NULL;
}

/*
 * Do the mount(2) system call.
 *
 * Returns 1 if successful, otherwise zero.
 * "errno" is set to reflect the individual error.
 */
static int nfs_sys_mount(const struct nfsmount_info *mi, const char *type,
			 const char *options)
{
	int result;

	result = mount(mi->spec, mi->node, type,
				mi->flags & ~(MS_USER|MS_USERS), options);
	if (verbose && result) {
		int save = errno;
		nfs_error(_("%s: mount(2): %s"), progname, strerror(save));
		errno = save;
	}
	return !result;
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
static int nfs_retry_nfs23mount(struct nfsmount_info *mi)
{
	struct mount_options *retry_options;
	char *retry_str = NULL;
	char **extra_opts = mi->extra_opts;

	retry_options = nfs_rewrite_mount_options(*extra_opts);
	if (!retry_options)
		return 0;

	if (po_join(retry_options, &retry_str) == PO_FAILED) {
		po_destroy(retry_options);
		errno = EIO;
		return 0;
	}

	if (verbose)
		printf(_("%s: text-based options (retry): '%s'\n"),
			progname, retry_str);

	if (!nfs_sys_mount(mi, "nfs", retry_str)) {
		po_destroy(retry_options);
		free(retry_str);
		return 0;
	}

	free(*extra_opts);
	*extra_opts = retry_str;
	po_replace(mi->options, retry_options);
	return 1;
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
static int nfs_try_nfs23mount(struct nfsmount_info *mi)
{
	char **extra_opts = mi->extra_opts;

	if (po_join(mi->options, extra_opts) == PO_FAILED) {
		errno = EIO;
		return 0;
	}

	if (verbose)
		printf(_("%s: text-based options: '%s'\n"),
			progname, *extra_opts);

	if (mi->fake)
		return 1;

	if (nfs_sys_mount(mi, "nfs", *extra_opts))
		return 1;

	/*
	 * The kernel returns EOPNOTSUPP if the RPC bind failed,
	 * and EPROTONOSUPPORT if the version isn't supported.
	 */
	if (errno != EOPNOTSUPP && errno != EPROTONOSUPPORT)
		return 0;

	return nfs_retry_nfs23mount(mi);
}

/*
 * Attempt an NFS v4 mount via a mount(2) system call.
 *
 * Returns 1 if successful.  Otherwise, returns zero.
 * "errno" is set to reflect the individual error.
 */
static int nfs_try_nfs4mount(struct nfsmount_info *mi)
{
	char **extra_opts = mi->extra_opts;

	if (po_join(mi->options, extra_opts) == PO_FAILED) {
		errno = EIO;
		return 0;
	}

	if (verbose)
		printf(_("%s: text-based options: '%s'\n"),
			progname, *extra_opts);

	if (mi->fake)
		return 1;

	return nfs_sys_mount(mi, "nfs4", *extra_opts);
}

/*
 * Perform either an NFSv2/3 mount, or an NFSv4 mount system call.
 *
 * Returns 1 if successful.  Otherwise, returns zero.
 * "errno" is set to reflect the individual error.
 */
static int nfs_try_mount(struct nfsmount_info *mi)
{
	if (strncmp(mi->type, "nfs4", 4) == 0)
		return nfs_try_nfs4mount(mi);
	else
		return nfs_try_nfs23mount(mi);
}

/*
 * Handle "foreground" NFS mounts.
 *
 * Retry the mount request for as long as the 'retry=' option says.
 *
 * Returns a valid mount command exit code.
 */
static int nfsmount_fg(struct nfsmount_info *mi)
{
	unsigned int secs = 1;
	time_t timeout;

	timeout = nfs_parse_retry_option(mi->options,
					 NFS_DEF_FG_TIMEOUT_MINUTES);
	if (verbose)
		printf(_("%s: timeout set for %s"),
			progname, ctime(&timeout));

	for (;;) {
		if (nfs_try_mount(mi))
			return EX_SUCCESS;

		if (nfs_is_permanent_error(errno))
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

	mount_error(mi->spec, mi->node, errno);
	return EX_FAIL;
}

/*
 * Handle "background" NFS mount [first try]
 *
 * Returns a valid mount command exit code.
 *
 * EX_BG should cause the caller to fork and invoke nfsmount_child.
 */
static int nfsmount_parent(struct nfsmount_info *mi)
{
	if (nfs_try_mount(mi))
		return EX_SUCCESS;

	if (nfs_is_permanent_error(errno)) {
		mount_error(mi->spec, mi->node, errno);
		return EX_FAIL;
	}

	sys_mount_errors(mi->hostname, errno, 1, 1);
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
static int nfsmount_child(struct nfsmount_info *mi)
{
	unsigned int secs = 1;
	time_t timeout;

	timeout = nfs_parse_retry_option(mi->options,
					 NFS_DEF_BG_TIMEOUT_MINUTES);

	for (;;) {
		if (sleep(secs))
			break;
		secs <<= 1;
		if (secs > 120)
			secs = 120;

		if (nfs_try_mount(mi))
			return EX_SUCCESS;

		if (nfs_is_permanent_error(errno))
			break;

		if (time(NULL) > timeout)
			break;

		sys_mount_errors(mi->hostname, errno, 1, 1);
	};

	sys_mount_errors(mi->hostname, errno, 1, 0);
	return EX_FAIL;
}

/*
 * Handle "background" NFS mount
 *
 * Returns a valid mount command exit code.
 */
static int nfsmount_bg(struct nfsmount_info *mi)
{
	if (!mi->child)
		return nfsmount_parent(mi);
	else
		return nfsmount_child(mi);
}

/*
 * Process mount options and try a mount system call.
 *
 * Returns a valid mount command exit code.
 */
static int nfsmount_start(struct nfsmount_info *mi)
{
	if (!nfs_validate_options(mi))
		return EX_FAIL;

	if (po_rightmost(mi->options, "bg", "fg") == PO_KEY1_RIGHTMOST)
		return nfsmount_bg(mi);
	else
		return nfsmount_fg(mi);
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
	struct nfsmount_info mi = {
		.spec		= spec,
		.node		= node,
		.type		= type,
		.extra_opts	= extra_opts,
		.flags		= flags,
		.fake		= fake,
		.child		= child,
#ifdef IPV6_SUPPORTED
		.family		= AF_UNSPEC,	/* either IPv4 or v6 */
#else
		.family		= AF_INET,	/* only IPv4 */
#endif
	};
	int retval = EX_FAIL;

	mi.options = po_split(*extra_opts);
	if (mi.options) {
		retval = nfsmount_start(&mi);
		po_destroy(mi.options);
	} else
		nfs_error(_("%s: internal option parsing error"), progname);

	free(mi.hostname);
	return retval;
}
