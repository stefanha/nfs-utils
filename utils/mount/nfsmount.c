/*
 * nfsmount.c -- Linux NFS mount
 * Copyright (C) 1993 Rick Sladkey <jrs@world.std.com>
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
 * Wed Feb  8 12:51:48 1995, biro@yggdrasil.com (Ross Biro): allow all port
 * numbers to be specified on the command line.
 *
 * Fri, 8 Mar 1996 18:01:39, Swen Thuemmler <swen@uni-paderborn.de>:
 * Omit the call to connect() for Linux version 1.3.11 or later.
 *
 * Wed Oct  1 23:55:28 1997: Dick Streefland <dick_streefland@tasking.com>
 * Implemented the "bg", "fg" and "retry" mount options for NFS.
 *
 * 1999-02-22 Arkadiusz Mi¶kiewicz <misiek@pld.ORG.PL>
 * - added Native Language Support
 * 
 * Modified by Olaf Kirch and Trond Myklebust for new NFS code,
 * plus NFSv3 stuff.
 *
 * 2006-06-06 Amit Gud <agud@redhat.com>
 * - Moved with modifcations to nfs-utils/utils/mount from util-linux/mount.
 */

/*
 * nfsmount.c,v 1.1.1.1 1993/11/18 08:40:51 jrs Exp
 */

#include <ctype.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>
#include <rpc/rpc.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_clnt.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mntent.h>
#include <sys/mount.h>
#include <paths.h>
#include <syslog.h>

#include "conn.h"
#include "xcommon.h"
#include "mount.h"
#include "nfsumount.h"
#include "nfs_mount.h"
#include "mount_constants.h"
#include "nls.h"

#ifdef HAVE_RPCSVC_NFS_PROT_H
#include <rpcsvc/nfs_prot.h>
#else
#include <linux/nfs.h>
#define nfsstat nfs_stat
#endif

#ifndef NFS_PORT
#define NFS_PORT 2049
#endif
#ifndef NFS_FHSIZE
#define NFS_FHSIZE 32
#endif

static char *nfs_strerror(int stat);

#define MAKE_VERSION(p,q,r)	(65536*(p) + 256*(q) + (r))
#define MAX_NFSPROT ((nfs_mount_version >= 4) ? 3 : 2)
#define MAX_MNTPROT ((nfs_mount_version >= 4) ? 3 : 2)
#define HAVE_RELIABLE_TCP (nfs_mount_version >= 4)

#ifndef HAVE_INET_ATON
#define inet_aton(a,b) (0)
#endif

typedef dirpath mnt2arg_t;
typedef dirpath mnt3arg_t;
typedef dirpath mntarg_t;

typedef struct fhstatus  mnt2res_t;
typedef struct mountres3 mnt3res_t;
typedef union {
	mnt2res_t nfsv2;
	mnt3res_t nfsv3;
} mntres_t;

static char errbuf[BUFSIZ];
static char *erreob = &errbuf[BUFSIZ];
extern int verbose;

/* Convert RPC errors into strings */
int rpc_strerror(int);
int rpc_strerror(int spos)
{
	int cf_stat = rpc_createerr.cf_stat; 
	int pos=0, cf_errno = rpc_createerr.cf_error.re_errno;
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
	return (pos);
}
void mount_errors(char *, int, int);
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

/* Define the order in which to probe for UDP/TCP services */
enum plist {
	use_tcp = 0,
	udp_tcp,
	udp_only,
};
static const u_int *
proto_probelist(enum plist list)
{
	static const u_int probe_udp_tcp[] = { IPPROTO_UDP, IPPROTO_TCP, 0 };
	static const u_int probe_both[] = { IPPROTO_TCP, IPPROTO_UDP, 0 };
	static const u_int probe_udponly[] = { IPPROTO_UDP, 0 };

	if (list == use_tcp)
		return probe_both;
	if (list == udp_tcp)
		return probe_udp_tcp;
	return probe_udponly;
}

/* Define the order in which NFS versions are probed on portmapper */
static const u_long *
nfs_probelist(const int vers)
{
	static const u_long nfs2_probe[] = { 2, 0};
	static const u_long nfs3_probe[] = { 3, 2, 0};
	switch (vers) {
	case 3:
		return nfs3_probe;
	default:
		return nfs2_probe;
	}
}

/* Define the order in which Mountd versions are probed on portmapper */
static const u_long *
mnt_probelist(const int vers)
{
	static const u_long mnt1_probe[] = { 1, 2, 0 };
	static const u_long mnt3_probe[] = { 3, 1, 2, 0 };
	switch (vers) {
	case 3:
		return mnt3_probe;
	default:
		return mnt1_probe;
	}
}

static int
linux_version_code(void) {
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
 * Unfortunately, the kernel prints annoying console messages
 * in case of an unexpected nfs mount version (instead of
 * just returning some error).  Therefore we'll have to try
 * and figure out what version the kernel expects.
 *
 * Variables:
 *	NFS_MOUNT_VERSION: these nfsmount sources at compile time
 *	nfs_mount_version: version this source and running kernel can handle
 */
int nfs_mount_version = NFS_MOUNT_VERSION;

int
find_kernel_nfs_mount_version(void) {
	static int kernel_version = -1;
	int mnt_version = NFS_MOUNT_VERSION;

	if (kernel_version == -1)
		kernel_version = linux_version_code();

	if (kernel_version) {
	     if (kernel_version < MAKE_VERSION(2,1,32))
		  mnt_version = 1;
	     else if (kernel_version < MAKE_VERSION(2,2,18))
		  mnt_version = 3;
	     else if (kernel_version < MAKE_VERSION(2,3,0))
		  mnt_version = 4; /* since 2.2.18pre9 */
	     else if (kernel_version < MAKE_VERSION(2,3,99))
		  mnt_version = 3;
	     else if (kernel_version < MAKE_VERSION(2,6,3))
		  mnt_version = 4;
	     else
		  mnt_version = 6;
	}
	if (mnt_version > NFS_MOUNT_VERSION)
	     mnt_version = NFS_MOUNT_VERSION;
	return mnt_version;
}

int nfs_gethostbyname(const char *, struct sockaddr_in *);
int nfs_gethostbyname(const char *hostname, struct sockaddr_in *saddr)
{
	struct hostent *hp;

	saddr->sin_family = AF_INET;
	if (!inet_aton(hostname, &saddr->sin_addr)) {
		if ((hp = gethostbyname(hostname)) == NULL) {
			fprintf(stderr, _("mount: can't get address for %s\n"),
				hostname);
			return 0;
		} else {
			if (hp->h_length > sizeof(*saddr)) {
				fprintf(stderr,
					_("mount: got bad hp->h_length\n"));
				hp->h_length = sizeof(*saddr);
			}
			memcpy(&saddr->sin_addr, hp->h_addr, hp->h_length);
		}
	}
	return 1;
}

/*
 * getport() is very similar to pmap_getport() with
 * the exception this version uses a non-reserve ports 
 * instead of reserve ports since reserve ports
 * are not needed for pmap requests.
 */
static u_short
getport(
	struct sockaddr_in *saddr, 
	u_long prog, 
	u_long vers, 
	u_int prot)
{
	u_short port;
	int    socket;
	CLIENT *clnt = NULL;
	struct pmap parms;
	enum clnt_stat stat;

	saddr->sin_port = htons (PMAPPORT);
	socket = get_socket(saddr, prot, FALSE);

	switch (prot) {
	case IPPROTO_UDP:
		clnt = clntudp_bufcreate(saddr,
					 PMAPPROG, PMAPVERS, TIMEOUT, &socket,
					 UDPMSGSIZE, UDPMSGSIZE);
		break;
	case IPPROTO_TCP:
		clnt = clnttcp_create(saddr,
			PMAPPROG, PMAPVERS, &socket, 50, 500);
		break;
	}
	if (clnt != NULL) {
		parms.pm_prog = prog;
		parms.pm_vers = vers;
		parms.pm_prot = prot;
		parms.pm_port = 0;    /* not needed or used */

		stat = clnt_call(clnt, PMAPPROC_GETPORT, (xdrproc_t)xdr_pmap,
			(caddr_t)&parms, (xdrproc_t)xdr_u_short, (caddr_t)&port, TIMEOUT);
		if (stat) {
			clnt_geterr(clnt, &rpc_createerr.cf_error);
			rpc_createerr.cf_stat = stat;
		}
		clnt_destroy(clnt);
		if (stat != RPC_SUCCESS)
			port = 0;
		else if (port == 0)
			rpc_createerr.cf_stat = RPC_PROGNOTREGISTERED;
	}
	if (socket != 1)
		close(socket);

	return port;
}

/*
 * Use the portmapper to discover whether or not the service we want is
 * available. The lists 'versions' and 'protos' define ordered sequences
 * of service versions and udp/tcp protocols to probe for.
 */
static int
probe_port(clnt_addr_t *server, 
	   const u_long *versions,
	   const u_int *protos)
{
	struct sockaddr_in *saddr = &server->saddr;
	struct pmap *pmap = &server->pmap;
	const u_long prog = pmap->pm_prog, *p_vers;
	const u_int prot = (u_int)pmap->pm_prot,
		*p_prot;
	const u_short port = (u_short) pmap->pm_port;
	u_long vers = pmap->pm_vers;
	u_short p_port;
	p_prot = prot ? &prot : protos;
	p_vers = vers ? &vers : versions;
	rpc_createerr.cf_stat = 0;
	for (;;) {
		saddr->sin_port = htons(PMAPPORT);
		p_port = getport(saddr, prog, *p_vers, *p_prot);
		if (p_port) {
			if (!port || port == p_port) {
				saddr->sin_port = htons(p_port);
				if (verbose) {
					fprintf(stderr, 
						"mount: trying %s prog %ld vers %ld prot %s port %d\n", 
						inet_ntoa(saddr->sin_addr), prog, *p_vers,
						*p_prot == IPPROTO_UDP ? "udp" : "tcp", p_port);
				}
				if (clnt_ping(saddr, prog, *p_vers, *p_prot, NULL))
					goto out_ok;
				if (rpc_createerr.cf_stat == RPC_TIMEDOUT)
					goto out_bad;
			}
		}
		if (rpc_createerr.cf_stat != RPC_PROGNOTREGISTERED) 
			goto out_bad;

		if (!prot) {
			if (*++p_prot)
				continue;
			p_prot = protos;
		}
		if (vers == pmap->pm_vers) {
			p_vers = versions;
			vers = 0;
		}
		if (vers || !*++p_vers)
			break;
	}
out_bad:
	return 0;

 out_ok:
	if (!vers)
		pmap->pm_vers = *p_vers;
	if (!prot)
		pmap->pm_prot = *p_prot;
	if (!port)
		pmap->pm_port = p_port;
	rpc_createerr.cf_stat = 0;
	return 1;
}

static int
probe_nfsport(clnt_addr_t *nfs_server)
{
	const struct pmap *pmap = &nfs_server->pmap;
	const u_long *probe_vers;
	const u_int *probe_prot;

	if (pmap->pm_vers && pmap->pm_prot && pmap->pm_port)
		return 1;
	probe_vers = nfs_probelist(MAX_NFSPROT);
	probe_prot = proto_probelist(HAVE_RELIABLE_TCP ? use_tcp : udp_only);
	return probe_port(nfs_server, probe_vers, probe_prot);
}

int probe_mntport(clnt_addr_t *mnt_server)
{
	const struct pmap *pmap = &mnt_server->pmap;
	const u_long *probe_vers;
	const u_int *probe_prot;

	if (pmap->pm_vers && pmap->pm_prot && pmap->pm_port)
		return 1;
	probe_vers = mnt_probelist(MAX_MNTPROT);
	probe_prot = proto_probelist(HAVE_RELIABLE_TCP ? udp_tcp : udp_only);
	return probe_port(mnt_server, probe_vers, probe_prot);
}

static int
probe_bothports(clnt_addr_t *mnt_server, clnt_addr_t *nfs_server)
{
	struct pmap *nfs_pmap = &nfs_server->pmap;
	struct pmap *mnt_pmap = &mnt_server->pmap;
	struct pmap save_nfs, save_mnt;
	int res;
	const u_long *probe_vers;

	if (mnt_pmap->pm_vers && !nfs_pmap->pm_vers)
		nfs_pmap->pm_vers = mntvers_to_nfs(mnt_pmap->pm_vers);
	else if (nfs_pmap->pm_vers && !mnt_pmap->pm_vers)
		mnt_pmap->pm_vers = nfsvers_to_mnt(nfs_pmap->pm_vers);
	if (nfs_pmap->pm_vers)
		goto version_fixed;
	memcpy(&save_nfs, nfs_pmap, sizeof(save_nfs));
	memcpy(&save_mnt, mnt_pmap, sizeof(save_mnt));
	for (probe_vers = mnt_probelist(MAX_MNTPROT); *probe_vers; probe_vers++) {
		nfs_pmap->pm_vers = mntvers_to_nfs(*probe_vers);
		if ((res = probe_nfsport(nfs_server) != 0)) {
			mnt_pmap->pm_vers = nfsvers_to_mnt(nfs_pmap->pm_vers);
			if ((res = probe_mntport(mnt_server)) != 0)
				return 1;
			memcpy(mnt_pmap, &save_mnt, sizeof(*mnt_pmap));
		}
		switch (rpc_createerr.cf_stat) {
		case RPC_PROGVERSMISMATCH:
		case RPC_PROGNOTREGISTERED:
			break;
		default:
			goto out_bad;
		}
		memcpy(nfs_pmap, &save_nfs, sizeof(*nfs_pmap));
	}
 out_bad:
	return 0;
 version_fixed:
	if (!probe_nfsport(nfs_server))
		goto out_bad;
	return probe_mntport(mnt_server);
}

static inline enum clnt_stat
nfs3_mount(CLIENT *clnt, mnt3arg_t *mnt3arg, mnt3res_t *mnt3res)
{
	return clnt_call(clnt, MOUNTPROC3_MNT,
			 (xdrproc_t) xdr_dirpath, (caddr_t) mnt3arg,
			 (xdrproc_t) xdr_mountres3, (caddr_t) mnt3res,
			 TIMEOUT);
}

static inline enum clnt_stat
nfs2_mount(CLIENT *clnt, mnt2arg_t *mnt2arg, mnt2res_t *mnt2res)
{
	return clnt_call(clnt, MOUNTPROC_MNT,
			 (xdrproc_t) xdr_dirpath, (caddr_t) mnt2arg,
			 (xdrproc_t) xdr_fhstatus, (caddr_t) mnt2res,
			 TIMEOUT);
}

static int
nfs_call_mount(clnt_addr_t *mnt_server, clnt_addr_t *nfs_server,
	       mntarg_t *mntarg, mntres_t *mntres)
{
	CLIENT *clnt;
	enum clnt_stat stat;
	int msock;

	if (!probe_bothports(mnt_server, nfs_server))
		goto out_bad;

	clnt = mnt_openclnt(mnt_server, &msock);
	if (!clnt)
		goto out_bad;
	/* make pointers in xdr_mountres3 NULL so
	 * that xdr_array allocates memory for us
	 */
	memset(mntres, 0, sizeof(*mntres));
	switch (mnt_server->pmap.pm_vers) {
	case 3:
		stat = nfs3_mount(clnt, mntarg, &mntres->nfsv3);
		break;
	case 2:
	case 1:
		stat = nfs2_mount(clnt, mntarg, &mntres->nfsv2);
		break;
	default:
		goto out_bad;
	}
	if (stat != RPC_SUCCESS) {
		clnt_geterr(clnt, &rpc_createerr.cf_error);
		rpc_createerr.cf_stat = stat;
	}
	mnt_closeclnt(clnt, msock);
	if (stat == RPC_SUCCESS)
		return 1;
 out_bad:
	return 0;
}

static int
parse_options(char *old_opts, struct nfs_mount_data *data,
	      int *bg, int *retry, clnt_addr_t *mnt_server,
	      clnt_addr_t *nfs_server, char *new_opts, const int opt_size)
{
	struct sockaddr_in *mnt_saddr = &mnt_server->saddr;
	struct pmap *mnt_pmap = &mnt_server->pmap;
	struct pmap *nfs_pmap = &nfs_server->pmap;
	int len;
	char *opt, *opteq;
	char *mounthost = NULL;
	char cbuf[128];

	data->flags = 0;
	*bg = 0;

	len = strlen(new_opts);
	for (opt = strtok(old_opts, ","); opt; opt = strtok(NULL, ",")) {
		if (strlen(opt) >= sizeof(cbuf))
			goto bad_parameter;
		if ((opteq = strchr(opt, '=')) && isdigit(opteq[1])) {
			int val = atoi(opteq + 1);	
			*opteq = '\0';
/* printf("opt=%s\n", opt); */
			if (!strcmp(opt, "rsize"))
				data->rsize = val;
			else if (!strcmp(opt, "wsize"))
				data->wsize = val;
			else if (!strcmp(opt, "timeo"))
				data->timeo = val;
			else if (!strcmp(opt, "retrans"))
				data->retrans = val;
			else if (!strcmp(opt, "acregmin"))
				data->acregmin = val;
			else if (!strcmp(opt, "acregmax"))
				data->acregmax = val;
			else if (!strcmp(opt, "acdirmin"))
				data->acdirmin = val;
			else if (!strcmp(opt, "acdirmax"))
				data->acdirmax = val;
			else if (!strcmp(opt, "actimeo")) {
				data->acregmin = val;
				data->acregmax = val;
				data->acdirmin = val;
				data->acdirmax = val;
			}
			else if (!strcmp(opt, "retry"))
				*retry = val;
			else if (!strcmp(opt, "port"))
				nfs_pmap->pm_port = val;
			else if (!strcmp(opt, "mountport"))
			        mnt_pmap->pm_port = val;
			else if (!strcmp(opt, "mountprog"))
				mnt_pmap->pm_prog = val;
			else if (!strcmp(opt, "mountvers"))
				mnt_pmap->pm_vers = val;
			else if (!strcmp(opt, "mounthost"))
				mounthost=xstrndup(opteq+1, strcspn(opteq+1," \t\n\r,"));
			else if (!strcmp(opt, "nfsprog"))
				nfs_pmap->pm_prog = val;
			else if (!strcmp(opt, "nfsvers") ||
				 !strcmp(opt, "vers")) {
				nfs_pmap->pm_vers = val;
				opt = "nfsvers";
#if NFS_MOUNT_VERSION >= 2
			} else if (!strcmp(opt, "namlen")) {
				if (nfs_mount_version >= 2)
					data->namlen = val;
				else
					goto bad_parameter;
#endif
			} else if (!strcmp(opt, "addr")) {
				/* ignore */;
				continue;
 			} else
				goto bad_parameter;
			sprintf(cbuf, "%s=%s,", opt, opteq+1);
		} else if (opteq) {
			*opteq = '\0';
			if (!strcmp(opt, "proto")) {
				if (!strcmp(opteq+1, "udp")) {
					nfs_pmap->pm_prot = IPPROTO_UDP;
					mnt_pmap->pm_prot = IPPROTO_UDP;
#if NFS_MOUNT_VERSION >= 2
					data->flags &= ~NFS_MOUNT_TCP;
				} else if (!strcmp(opteq+1, "tcp") &&
					   nfs_mount_version > 2) {
					nfs_pmap->pm_prot = IPPROTO_TCP;
					mnt_pmap->pm_prot = IPPROTO_TCP;
					data->flags |= NFS_MOUNT_TCP;
#endif
				} else
					goto bad_parameter;
#if NFS_MOUNT_VERSION >= 5
			} else if (!strcmp(opt, "sec")) {
				char *secflavor = opteq+1;
				/* see RFC 2623 */
				if (nfs_mount_version < 5) {
					printf(_("Warning: ignoring sec=%s option\n"), secflavor);
					continue;
				} else if (!strcmp(secflavor, "sys"))
					data->pseudoflavor = AUTH_SYS;
				else if (!strcmp(secflavor, "krb5"))
					data->pseudoflavor = AUTH_GSS_KRB5;
				else if (!strcmp(secflavor, "krb5i"))
					data->pseudoflavor = AUTH_GSS_KRB5I;
				else if (!strcmp(secflavor, "krb5p"))
					data->pseudoflavor = AUTH_GSS_KRB5P;
				else if (!strcmp(secflavor, "lipkey"))
					data->pseudoflavor = AUTH_GSS_LKEY;
				else if (!strcmp(secflavor, "lipkey-i"))
					data->pseudoflavor = AUTH_GSS_LKEYI;
				else if (!strcmp(secflavor, "lipkey-p"))
					data->pseudoflavor = AUTH_GSS_LKEYP;
				else if (!strcmp(secflavor, "spkm3"))
					data->pseudoflavor = AUTH_GSS_SPKM;
				else if (!strcmp(secflavor, "spkm3i"))
					data->pseudoflavor = AUTH_GSS_SPKMI;
				else if (!strcmp(secflavor, "spkm3p"))
					data->pseudoflavor = AUTH_GSS_SPKMP;
				else {
					printf(_("Warning: Unrecognized security flavor %s.\n"),
						secflavor);
					goto bad_parameter;
				}
				data->flags |= NFS_MOUNT_SECFLAVOUR;
#endif
			} else if (!strcmp(opt, "mounthost"))
			        mounthost=xstrndup(opteq+1,
						   strcspn(opteq+1," \t\n\r,"));
			 else if (!strcmp(opt, "context")) {
 				char *context = opteq + 1;
 				
 				if (strlen(context) > NFS_MAX_CONTEXT_LEN) {
 					printf(_("context parameter exceeds limit of %d\n"),
 						 NFS_MAX_CONTEXT_LEN);
					goto bad_parameter;
 				}
 				strncpy(data->context, context, NFS_MAX_CONTEXT_LEN);
 			} else
				goto bad_parameter;
			sprintf(cbuf, "%s=%s,", opt, opteq+1);
		} else {
			int val = 1;
			if (!strncmp(opt, "no", 2)) {
				val = 0;
				opt += 2;
			}
			if (!strcmp(opt, "bg")) 
				*bg = val;
			else if (!strcmp(opt, "fg")) 
				*bg = !val;
			else if (!strcmp(opt, "soft")) {
				data->flags &= ~NFS_MOUNT_SOFT;
				if (val)
					data->flags |= NFS_MOUNT_SOFT;
			} else if (!strcmp(opt, "hard")) {
				data->flags &= ~NFS_MOUNT_SOFT;
				if (!val)
					data->flags |= NFS_MOUNT_SOFT;
			} else if (!strcmp(opt, "intr")) {
				data->flags &= ~NFS_MOUNT_INTR;
				if (val)
					data->flags |= NFS_MOUNT_INTR;
			} else if (!strcmp(opt, "posix")) {
				data->flags &= ~NFS_MOUNT_POSIX;
				if (val)
					data->flags |= NFS_MOUNT_POSIX;
			} else if (!strcmp(opt, "cto")) {
				data->flags &= ~NFS_MOUNT_NOCTO;
				if (!val)
					data->flags |= NFS_MOUNT_NOCTO;
			} else if (!strcmp(opt, "ac")) {
				data->flags &= ~NFS_MOUNT_NOAC;
				if (!val)
					data->flags |= NFS_MOUNT_NOAC;
#if NFS_MOUNT_VERSION >= 2
			} else if (!strcmp(opt, "tcp")) {
				data->flags &= ~NFS_MOUNT_TCP;
				if (val) {
					if (nfs_mount_version < 2)
						goto bad_option;
					nfs_pmap->pm_prot = IPPROTO_TCP;
					mnt_pmap->pm_prot = IPPROTO_TCP;
					data->flags |= NFS_MOUNT_TCP;
				} else {
					mnt_pmap->pm_prot = IPPROTO_UDP;
					nfs_pmap->pm_prot = IPPROTO_UDP;
				}
			} else if (!strcmp(opt, "udp")) {
				data->flags &= ~NFS_MOUNT_TCP;
				if (!val) {
					if (nfs_mount_version < 2)
						goto bad_option;
					nfs_pmap->pm_prot = IPPROTO_TCP;
					mnt_pmap->pm_prot = IPPROTO_TCP;
					data->flags |= NFS_MOUNT_TCP;
				} else {
					nfs_pmap->pm_prot = IPPROTO_UDP;
					mnt_pmap->pm_prot = IPPROTO_UDP;
				}
#endif
#if NFS_MOUNT_VERSION >= 3
			} else if (!strcmp(opt, "lock")) {
				data->flags &= ~NFS_MOUNT_NONLM;
				if (!val) {
					if (nfs_mount_version < 3)
						goto bad_option;
					data->flags |= NFS_MOUNT_NONLM;
				}
#endif
#if NFS_MOUNT_VERSION >= 4
			} else if (!strcmp(opt, "broken_suid")) {
				data->flags &= ~NFS_MOUNT_BROKEN_SUID;
				if (val) {
					if (nfs_mount_version < 4)
						goto bad_option;
					data->flags |= NFS_MOUNT_BROKEN_SUID;
				}
			} else if (!strcmp(opt, "acl")) {
				data->flags &= ~NFS_MOUNT_NOACL;
				if (!val)
					data->flags |= NFS_MOUNT_NOACL;
#endif
			} else {
			bad_option:
				printf(_("Unsupported nfs mount option: "
					 "%s%s\n"), val ? "" : "no", opt);
				goto out_bad;
			}
			sprintf(cbuf, val ? "%s,":"no%s,", opt);
		}
		len += strlen(cbuf);
		if (len >= opt_size) {
			printf(_("mount: excessively long option argument\n"));
			goto out_bad;
		}
		strcat(new_opts, cbuf);
	}
	/* See if the nfs host = mount host. */
	if (mounthost) {
		if (!nfs_gethostbyname(mounthost, mnt_saddr))
			goto out_bad;
		*mnt_server->hostname = mounthost;
	}
	return 1;
 bad_parameter:
	printf(_("Bad nfs mount parameter: %s\n"), opt);
 out_bad:
	return 0;
}

static inline int
nfsmnt_check_compat(const struct pmap *nfs_pmap, const struct pmap *mnt_pmap)
{
	if (nfs_pmap->pm_vers && 
		(nfs_pmap->pm_vers > MAX_NFSPROT || nfs_pmap->pm_vers < 2)) {
		if (nfs_pmap->pm_vers == 4)
			fprintf(stderr, _("'vers=4' is not supported.  "
				"Use '-t nfs4' instead.\n"));
		else
			fprintf(stderr, _("NFS version %ld is not supported.\n"), 
				nfs_pmap->pm_vers);
		goto out_bad;
	}
	if (mnt_pmap->pm_vers > MAX_MNTPROT) {
		fprintf(stderr, _("NFS mount version %ld s not supported.\n"), 
			mnt_pmap->pm_vers);
		goto out_bad;
	}
	return 1;
 out_bad:
	return 0;
}

int
nfsmount(const char *spec, const char *node, int *flags,
	 char **extra_opts, char **mount_opts, int *nfs_mount_vers,
	 int running_bg)
{
	static char *prev_bg_host;
	char hostdir[1024];
	char *hostname, *dirname, *old_opts, *mounthost = NULL;
	char new_opts[1024], cbuf[1024];
	static struct nfs_mount_data data;
	int val;
	static int doonce = 0;

	clnt_addr_t mnt_server = { &mounthost, };
	clnt_addr_t nfs_server = { &hostname, };
	struct sockaddr_in *nfs_saddr = &nfs_server.saddr;
	struct pmap  *mnt_pmap = &mnt_server.pmap, 
		     *nfs_pmap = &nfs_server.pmap;
	struct pmap  save_mnt, save_nfs;

	int fsock;

	mntres_t mntres;

	struct stat statbuf;
	char *s;
	int bg, retry;
	int retval;
	time_t t;
	time_t prevt;
	time_t timeout;

	/* The version to try is either specified or 0
	   In case it is 0 we tell the caller what we tried */
	if (!*nfs_mount_vers)
		*nfs_mount_vers = find_kernel_nfs_mount_version();
	nfs_mount_version = *nfs_mount_vers;

	retval = EX_FAIL;
	fsock = -1;
	if (strlen(spec) >= sizeof(hostdir)) {
		fprintf(stderr, _("mount: "
				  "excessively long host:dir argument\n"));
		goto fail;
	}
	strcpy(hostdir, spec);
	if ((s = strchr(hostdir, ':'))) {
		hostname = hostdir;
		dirname = s + 1;
		*s = '\0';
		/* Ignore all but first hostname in replicated mounts
		   until they can be fully supported. (mack@sgi.com) */
		if ((s = strchr(hostdir, ','))) {
			*s = '\0';
			fprintf(stderr,
				_("mount: warning: "
				  "multiple hostnames not supported\n"));
		}
	} else {
		fprintf(stderr,
			_("mount: "
			  "directory to mount not in host:dir format\n"));
		goto fail;
	}

	if (!nfs_gethostbyname(hostname, nfs_saddr))
		goto fail;
	mounthost = hostname;
	memcpy (&mnt_server.saddr, nfs_saddr, sizeof (mnt_server.saddr));

	/* add IP address to mtab options for use when unmounting */

	s = inet_ntoa(nfs_saddr->sin_addr);
	old_opts = *extra_opts;
	if (!old_opts)
		old_opts = "";

	/* Set default options.
	 * rsize/wsize (and bsize, for ver >= 3) are left 0 in order to
	 * let the kernel decide.
	 * timeo is filled in after we know whether it'll be TCP or UDP. */
	memset(&data, 0, sizeof(data));
	data.acregmin	= 3;
	data.acregmax	= 60;
	data.acdirmin	= 30;
	data.acdirmax	= 60;
#if NFS_MOUNT_VERSION >= 2
	data.namlen	= NAME_MAX;
#endif
	data.pseudoflavor = AUTH_SYS;

	bg = 0;
	retry = 10000;		/* 10000 minutes ~ 1 week */

	memset(mnt_pmap, 0, sizeof(*mnt_pmap));
	mnt_pmap->pm_prog = MOUNTPROG;
	memset(nfs_pmap, 0, sizeof(*nfs_pmap));
	nfs_pmap->pm_prog = NFS_PROGRAM;

	/* parse options */
	new_opts[0] = 0;
	if (!parse_options(old_opts, &data, &bg, &retry, &mnt_server, &nfs_server,
			   new_opts, sizeof(new_opts)))
		goto fail;
	if (!nfsmnt_check_compat(nfs_pmap, mnt_pmap))
		goto fail;
	
	if (retry == 10000 && !bg)
		retry = 2; /* reset for fg mounts */
	

#ifdef NFS_MOUNT_DEBUG
	printf("rsize = %d, wsize = %d, timeo = %d, retrans = %d\n",
	       data.rsize, data.wsize, data.timeo, data.retrans);
	printf("acreg (min, max) = (%d, %d), acdir (min, max) = (%d, %d)\n",
	       data.acregmin, data.acregmax, data.acdirmin, data.acdirmax);
	printf("port = %d, bg = %d, retry = %d, flags = %.8x\n",
	       nfs_pmap->pm_port, bg, retry, data.flags);
	printf("mountprog = %d, mountvers = %d, nfsprog = %d, nfsvers = %d\n",
	       mnt_pmap->pm_prog, mnt_pmap->pm_vers,
	       nfs_pmap->pm_prog, nfs_pmap->pm_vers);
	printf("soft = %d, intr = %d, posix = %d, nocto = %d, noac = %d ",
	       (data.flags & NFS_MOUNT_SOFT) != 0,
	       (data.flags & NFS_MOUNT_INTR) != 0,
	       (data.flags & NFS_MOUNT_POSIX) != 0,
	       (data.flags & NFS_MOUNT_NOCTO) != 0,
	       (data.flags & NFS_MOUNT_NOAC) != 0);
#if NFS_MOUNT_VERSION >= 2
	printf("tcp = %d ",
	       (data.flags & NFS_MOUNT_TCP) != 0);
#endif
#if NFS_MOUNT_VERSION >= 4
	printf("noacl = %d ", (data.flags & NFS_MOUNT_NOACL) != 0);
#endif
#if NFS_MOUNT_VERSION >= 5
	printf("sec = %u ", data.pseudoflavor);
#endif
	printf("\n");
#endif

	data.version = nfs_mount_version;
	*mount_opts = (char *) &data;

	if (*flags & MS_REMOUNT)
		goto out_ok;

	/*
	 * If the previous mount operation on the same host was
	 * backgrounded, and the "bg" for this mount is also set,
	 * give up immediately, to avoid the initial timeout.
	 */
	if (bg && !running_bg &&
	    prev_bg_host && strcmp(hostname, prev_bg_host) == 0) {
		if (retry > 0)
			retval = EX_BG;
		return retval;
	}

	/* create mount deamon client */

	/*
	 * The following loop implements the mount retries. On the first
	 * call, "running_bg" is 0. When the mount times out, and the
	 * "bg" option is set, the exit status EX_BG will be returned.
	 * For a backgrounded mount, there will be a second call by the
	 * child process with "running_bg" set to 1.
	 *
	 * The case where the mount point is not present and the "bg"
	 * option is set, is treated as a timeout. This is done to
	 * support nested mounts.
	 *
	 * The "retry" count specified by the user is the number of
	 * minutes to retry before giving up.
	 *
	 * Only the first error message will be displayed.
	 */
	timeout = time(NULL) + 60 * retry;
	prevt = 0;
	t = 30;
	val = 1;

	memcpy(&save_nfs, nfs_pmap, sizeof(save_nfs));
	memcpy(&save_mnt, mnt_pmap, sizeof(save_mnt));
	for (;;) {
		if (bg && stat(node, &statbuf) == -1) {
			/* no mount point yet - sleep */
			if (running_bg) {
				sleep(val);	/* 1, 2, 4, 8, 16, 30, ... */
				val *= 2;
				if (val > 30)
					val = 30;
			}
		} else {
			int stat;
			/* be careful not to use too many CPU cycles */
			if (t - prevt < 30)
				sleep(30);

			stat = nfs_call_mount(&mnt_server, &nfs_server,
					      &dirname, &mntres);
			if (stat)
				break;
			memcpy(nfs_pmap, &save_nfs, sizeof(*nfs_pmap));
			memcpy(mnt_pmap, &save_mnt, sizeof(*mnt_pmap));
			prevt = t;
		}
		if (!bg) {
			switch(rpc_createerr.cf_stat){
			case RPC_TIMEDOUT:
				break;
			case RPC_SYSTEMERROR:
				if (errno == ETIMEDOUT)
					break;
			default:
				mount_errors(*nfs_server.hostname, 0, bg);
		        goto fail;
			}
			t = time(NULL);
			if (t >= timeout) {
				mount_errors(*nfs_server.hostname, 0, bg);
				goto fail;
			}
			mount_errors(*nfs_server.hostname, 1, bg);
			continue;
		}
		if (!running_bg) {
			prev_bg_host = xstrdup(hostname);
			if (retry > 0)
				retval = EX_BG;
			goto fail;
		}
		t = time(NULL);
		if (t >= timeout) {
			mount_errors(*nfs_server.hostname, 0, bg);
			goto fail;
		}
		if (doonce++ < 1)
			mount_errors(*nfs_server.hostname, 1, bg);
	}

	if (nfs_pmap->pm_vers == 2) {
		if (mntres.nfsv2.fhs_status != 0) {
			fprintf(stderr,
				_("mount: %s:%s failed, reason given by server: %s\n"),
				hostname, dirname,
				nfs_strerror(mntres.nfsv2.fhs_status));
			goto fail;
		}
		memcpy(data.root.data,
		       (char *) mntres.nfsv2.fhstatus_u.fhs_fhandle,
		       NFS_FHSIZE);
#if NFS_MOUNT_VERSION >= 4
		data.root.size = NFS_FHSIZE;
		memcpy(data.old_root.data,
		       (char *) mntres.nfsv2.fhstatus_u.fhs_fhandle,
		       NFS_FHSIZE);
#endif
	} else {
#if NFS_MOUNT_VERSION >= 4
		mountres3_ok *mountres;
		fhandle3 *fhandle;
		int i, *flavor, yum = 0;
		if (mntres.nfsv3.fhs_status != 0) {
			fprintf(stderr,
				_("mount: %s:%s failed, reason given by server: %s\n"),
				hostname, dirname,
				nfs_strerror(mntres.nfsv3.fhs_status));
			goto fail;
		}
#if NFS_MOUNT_VERSION >= 5
		mountres = &mntres.nfsv3.mountres3_u.mountinfo;
		i = mountres->auth_flavors.auth_flavors_len;
		if (i <= 0) 
			goto noauth_flavors;

		flavor = mountres->auth_flavors.auth_flavors_val;
		while (--i >= 0) {
			if (flavor[i] == data.pseudoflavor)
				yum = 1;
#ifdef NFS_MOUNT_DEBUG
			printf("auth flavor %d: %d\n",
				i, flavor[i]);
#endif
		}
		if (!yum) {
			fprintf(stderr,
				"mount: %s:%s failed, "
				"security flavor not supported\n",
				hostname, dirname);
			/* server has registered us in mtab, send umount */
			nfs_call_umount(&mnt_server, &dirname);
			goto fail;
		}
noauth_flavors:
#endif
		fhandle = &mntres.nfsv3.mountres3_u.mountinfo.fhandle;
		memset(data.old_root.data, 0, NFS_FHSIZE);
		memset(&data.root, 0, sizeof(data.root));
		data.root.size = fhandle->fhandle3_len;
		memcpy(data.root.data,
		       (char *) fhandle->fhandle3_val,
		       fhandle->fhandle3_len);

		data.flags |= NFS_MOUNT_VER3;
#endif
	}

	/* create nfs socket for kernel */

	if (nfs_pmap->pm_prot == IPPROTO_TCP)
		fsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	else
		fsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fsock < 0) {
		perror(_("nfs socket"));
		goto fail;
	}
	if (bindresvport(fsock, 0) < 0) {
		perror(_("nfs bindresvport"));
		goto fail;
	}
#ifdef NFS_MOUNT_DEBUG
	printf(_("using port %d for nfs deamon\n"), nfs_pmap->pm_port);
#endif
	nfs_saddr->sin_port = htons(nfs_pmap->pm_port);
	/*
	 * connect() the socket for kernels 1.3.10 and below only,
	 * to avoid problems with multihomed hosts.
	 * --Swen
	 */
	if (linux_version_code() <= 66314
	    && connect(fsock, (struct sockaddr *) nfs_saddr,
		       sizeof (*nfs_saddr)) < 0) {
		perror(_("nfs connect"));
		goto fail;
	}

#if NFS_MOUNT_VERSION >= 2
	if (nfs_pmap->pm_prot == IPPROTO_TCP)
		data.flags |= NFS_MOUNT_TCP;
	else
		data.flags &= ~NFS_MOUNT_TCP;
#endif

	/* prepare data structure for kernel */

	data.fd = fsock;
	memcpy((char *) &data.addr, (char *) nfs_saddr, sizeof(data.addr));
	strncpy(data.hostname, hostname, sizeof(data.hostname));

 out_ok:
	/* Ensure we have enough padding for the following strcat()s */
	if (strlen(new_opts) + strlen(s) + 30 >= sizeof(new_opts)) {
		fprintf(stderr, _("mount: "
				  "excessively long option argument\n"));
		goto fail;
	}

	snprintf(cbuf, sizeof(cbuf)-1, "addr=%s", s);
	strcat(new_opts, cbuf);

	*extra_opts = xstrdup(new_opts);
	return 0;

	/* abort */
 fail:
	if (fsock != -1)
		close(fsock);
	return retval;
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

static char *nfs_strerror(int stat)
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
