/*
 * nfsstat.c		Output NFS statistics
 *
 * Copyright (C) 1995, 1996, 1999 Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"

#define NFSSVCSTAT	"/proc/net/rpc/nfsd"
#define NFSCLTSTAT	"/proc/net/rpc/nfs"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#define MAXNRVALS	32

static unsigned int	svcv2info[19];	/* NFSv2 call counts ([0] == 18) */
static unsigned int	cltv2info[19];	/* NFSv2 call counts ([0] == 18) */
static unsigned int	svcv3info[23];	/* NFSv3 call counts ([0] == 22) */
static unsigned int	cltv3info[23];	/* NFSv3 call counts ([0] == 22) */
static unsigned int	svcnetinfo[4];	/* 0  # of received packets
					 * 1  UDP packets
					 * 2  TCP packets
					 * 3  TCP connections
					 */
static unsigned int	cltnetinfo[4];	/* 0  # of received packets
					 * 1  UDP packets
					 * 2  TCP packets
					 * 3  TCP connections
					 */

static unsigned int	svcrpcinfo[5];	/* 0  total # of RPC calls
					 * 1  total # of bad calls
					 * 2  bad format
					 * 3  authentication failed
					 * 4  unknown client
					 */
static unsigned int	cltrpcinfo[3];	/* 0  total # of RPC calls
					 * 1  retransmitted calls
					 * 2  cred refreshs
					 */

static unsigned int	svcrcinfo[8];	/* 0  repcache hits
					 * 1  repcache hits
					 * 2  uncached reqs
					 * (for pre-2.4 kernels:)
					 * 3  FH lookups
					 * 4  'anon' FHs
					 * 5  noncached non-directories
					 * 6  noncached directories
					 * 7  stale
					 */

static unsigned int	svcfhinfo[6];	/* (for kernels >= 2.4.0)
					 * 0  stale
					 * 1  FH lookups
					 * 2  'anon' FHs
					 * 3  noncached directories
					 * 4  noncached non-directories
					 * leave hole to relocate stale for order
					 *    compatability.
					 */

static const char *	nfsv2name[18] = {
	"null", "getattr", "setattr", "root",   "lookup",  "readlink",
	"read", "wrcache", "write",   "create", "remove",  "rename",
	"link", "symlink", "mkdir",   "rmdir",  "readdir", "fsstat"
};

static const char *	nfsv3name[22] = {
	"null",   "getattr", "setattr",  "lookup", "access",  "readlink",
	"read",   "write",   "create",   "mkdir",  "symlink", "mknod",
	"remove", "rmdir",   "rename",   "link",   "readdir", "readdirplus",
	"fsstat", "fsinfo",  "pathconf", "commit"
};

typedef struct statinfo {
	char		*tag;
	int		nrvals;
	unsigned int *	valptr;
} statinfo;

static statinfo		svcinfo[] = {
	{ "net",	4,	svcnetinfo	},
	{ "rpc",	5,	svcrpcinfo	},
	{ "rc",		8,	svcrcinfo	},
	{ "fh",		5,	svcfhinfo	},
	{ "proc2",	19,	svcv2info	},
	{ "proc3",	23,	svcv3info	},
	{ NULL,		0,	0		}
};

static statinfo		cltinfo[] = {
	{ "net",	4,	cltnetinfo	},
	{ "rpc",	3,	cltrpcinfo	},
	{ "proc2",	19,	cltv2info	},
	{ "proc3",	23,	cltv3info	},
	{ NULL,		0,	0		}
};

static void		print_numbers(const char *, unsigned int *,
					unsigned int);
static void		print_callstats(const char *, const char **,
					unsigned int *, unsigned int);
static int		parse_statfile(const char *, struct statinfo *);

static statinfo		*get_stat_info(const char *, struct statinfo *);


#define PRNT_CALLS	0x0001
#define PRNT_RPC	0x0002
#define PRNT_NET	0x0004
#define PRNT_FH		0x0008
#define PRNT_RC		0x0010
#define PRNT_ALL	0xffff

int
main(int argc, char **argv)
{
	int		opt_all = 0,
			opt_srv = 0,
			opt_clt = 0,
			srv_info = 0,
			clt_info = 0,
			opt_prt = 0;
	int		c;

	while ((c = getopt(argc, argv, "acno:rsz")) != -1) {
		switch (c) {
		case 'a':
			opt_all = 1;
			break;
		case 'c':
			opt_clt = 1;
			break;
		case 'n':
			opt_prt |= PRNT_CALLS;
			break;
		case 'o':
			if (!strcmp(optarg, "nfs"))
				opt_prt |= PRNT_CALLS;
			else if (!strcmp(optarg, "rpc"))
				opt_prt |= PRNT_RPC;
			else if (!strcmp(optarg, "net"))
				opt_prt |= PRNT_NET;
			else if (!strcmp(optarg, "rc"))
				opt_prt |= PRNT_RC;
			else if (!strcmp(optarg, "fh"))
				opt_prt |= PRNT_FH;
			else {
				fprintf(stderr, "nfsstat: unknown category: "
						"%s\n", optarg);
				return 2;
			}
			break;
		case 'r':
			opt_prt |= PRNT_RPC;
			break;
		case 's':
			opt_srv = 1;
			break;
		case 'z':
			fprintf(stderr, "nfsstat: zeroing of nfs statistics "
					"not yet supported\n");
			return 2;
		}
	}

	if (opt_all) {
		opt_srv = opt_clt = 1;
		opt_prt = PRNT_ALL;
	}
	if (!(opt_srv + opt_clt))
		opt_srv = opt_clt = 1;
	if (!opt_prt)
		opt_prt = PRNT_CALLS + PRNT_RPC;
	if ((opt_prt & (PRNT_FH|PRNT_RC)) && !opt_srv) {
		fprintf(stderr,
			"You requested file handle or request cache "
			"statistics while using the -c option.\n"
			"This information is available only for the NFS "
			"server.\n");
	}

	if (opt_srv) {
		srv_info = parse_statfile(NFSSVCSTAT, svcinfo);
		if (srv_info == 0 && opt_clt == 0) {
			fprintf(stderr, "Warning: No Server Stats (%s: %m).\n", NFSSVCSTAT);
			return 2;
		}
		if (srv_info == 0)
			opt_srv = 0;
	}

	if (opt_clt) {
		clt_info = parse_statfile(NFSCLTSTAT, cltinfo);
		if (opt_srv == 0 && clt_info == 0) {
			fprintf(stderr, "Warning: No Client Stats (%s: %m).\n", NFSCLTSTAT);
			return 2;
		}
		if (clt_info == 0)
			opt_clt = 0;
	}

	if (opt_srv) {
		if (opt_prt & PRNT_NET) {
			print_numbers(
			"Server packet stats:\n"
			"packets    udp        tcp        tcpconn\n",
			svcnetinfo, 4
			);
		}
		if (opt_prt & PRNT_RPC) {
			print_numbers(
			"Server rpc stats:\n"
			"calls      badcalls   badauth    badclnt    xdrcall\n",
			svcrpcinfo, 5
			);
		}
		if (opt_prt & PRNT_RC) {
			print_numbers(
			"Server reply cache:\n"
			"hits       misses     nocache\n",
			svcrcinfo, 3
			);
		}

		/*
		 * 2.2 puts all fh-related info after the 'rc' header
		 * 2.4 puts all fh-related info after the 'fh' header, but relocates
		 *     'stale' to the start and swaps dir and nondir :-(  
		 *     We preseve the 2.2 order
		 */
		if (opt_prt & PRNT_FH) {
			if (get_stat_info("fh", svcinfo)) {	/* >= 2.4 */
				int t = svcfhinfo[3];
				svcfhinfo[3]=svcfhinfo[4];
				svcfhinfo[4]=t;
				
				svcfhinfo[5]=svcfhinfo[0]; /* relocate 'stale' */
				
				print_numbers(
					"Server file handle cache:\n"
					"lookup     anon       ncachedir ncachedir  stale\n",
					svcfhinfo + 1, 5);
			} else					/* < 2.4 */
				print_numbers(
					"Server file handle cache:\n"
					"lookup     anon       ncachedir ncachedir  stale\n",
					svcrcinfo + 3, 5);
		}
		if (opt_prt & PRNT_CALLS) {
			print_callstats(
			"Server nfs v2:\n",
			nfsv2name, svcv2info + 1, 18
			);
			if (svcv3info[0])
				print_callstats(
				"Server nfs v3:\n",
				nfsv3name, svcv3info + 1, 22
				);
		}
	}

	if (opt_clt) {
		if (opt_prt & PRNT_NET) {
			print_numbers(
			"Client packet stats:\n"
			"packets    udp        tcp        tcpconn\n",
			cltnetinfo, 4
			);
		}
		if (opt_prt & PRNT_RPC) {
			print_numbers(
			"Client rpc stats:\n"
			"calls      retrans    authrefrsh\n",
			cltrpcinfo, 3
			);
		}
		if (opt_prt & PRNT_CALLS) {
			print_callstats(
			"Client nfs v2:\n",
			nfsv2name, cltv2info + 1, 18
			);
			if (cltv3info[0])
				print_callstats(
				"Client nfs v3:\n",
				nfsv3name, cltv3info + 1, 22
				);
		}
	}

	return 0;
}

static statinfo *
get_stat_info(const char *sp, struct statinfo *statp)
{
	struct statinfo *ip;

	for (ip = statp; ip->tag; ip++) {
		if (!strcmp(sp, ip->tag))
			return ip;
	}

	return NULL;
}

static void
print_numbers(const char *hdr, unsigned int *info, unsigned int nr)
{
	unsigned int	i;

	fputs(hdr, stdout);
	for (i = 0; i < nr; i++)
		printf("%s%-8d", i? "   " : "", info[i]);
	printf("\n");
}

static void
print_callstats(const char *hdr, const char **names,
				 unsigned int *info, unsigned int nr)
{
	unsigned long long	total;
	unsigned long long	pct;
	int		i, j;

	fputs(hdr, stdout);
	for (i = 0, total = 0; i < nr; i++)
		total += info[i];
	if (!total)
		total = 1;
	for (i = 0; i < nr; i += 6) {
		for (j = 0; j < 6 && i + j < nr; j++)
			printf("%-11s", names[i+j]);
		printf("\n");
		for (j = 0; j < 6 && i + j < nr; j++) {
			pct = ((unsigned long long) info[i+j]*100)/total;
			printf("%-6d %2llu%% ", info[i+j], pct);
		}
		printf("\n");
	}
	printf("\n");
}


static int
parse_statfile(const char *name, struct statinfo *statp)
{
	char	buffer[4096], *next;
	FILE	*fp;

	/* Being unable to read e.g. the nfsd stats file shouldn't
	 * be a fatal error -- it usually means the module isn't loaded.
	 */
	if ((fp = fopen(name, "r")) == NULL) {
		// fprintf(stderr, "Warning: %s: %m\n", name);
		return 0;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		struct statinfo	*ip;
		char		*sp, *line = buffer;
		int		i, cnt;

		if ((next = strchr(line, '\n')) != NULL)
			*next++ = '\0';
		if (!(sp = strtok(line, " \t")))
			continue;

		ip = get_stat_info(sp, statp);
		if (!ip)
			continue;

		cnt = ip->nrvals;

		for (i = 0; i < cnt; i++) {
			if (!(sp = strtok(NULL, " \t")))
				break;
			ip->valptr[i] = atoi(sp);
		}
	}

	fclose(fp);
	return 1;
}
