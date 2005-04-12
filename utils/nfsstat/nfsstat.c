/*
 * nfsstat.c		Output NFS statistics
 *
 * Copyright (C) 1995-2005 Olaf Kirch <okir@suse.de>
 */

#include "config.h"

#define NFSSVCSTAT	"/proc/net/rpc/nfsd"
#define NFSCLTSTAT	"/proc/net/rpc/nfs"

#define MOUNTSFILE	"/proc/mounts"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#define MAXNRVALS	32

static unsigned int	svcv2info[20];	/* NFSv2 call counts ([0] == 18) */
static unsigned int	cltv2info[20];	/* NFSv2 call counts ([0] == 18) */
static unsigned int	svcv3info[24];	/* NFSv3 call counts ([0] == 22) */
static unsigned int	cltv3info[24];	/* NFSv3 call counts ([0] == 22) */
static unsigned int	svcv4info[4];	/* NFSv4 call counts ([0] == 2) */
static unsigned int	cltv4info[34];	/* NFSv4 call counts ([0] == 32) */
static unsigned int	svcnetinfo[5];	/* 0  # of received packets
					 * 1  UDP packets
					 * 2  TCP packets
					 * 3  TCP connections
					 */
static unsigned int	cltnetinfo[5];	/* 0  # of received packets
					 * 1  UDP packets
					 * 2  TCP packets
					 * 3  TCP connections
					 */

static unsigned int	svcrpcinfo[6];	/* 0  total # of RPC calls
					 * 1  total # of bad calls
					 * 2  bad format
					 * 3  authentication failed
					 * 4  unknown client
					 */
static unsigned int	cltrpcinfo[4];	/* 0  total # of RPC calls
					 * 1  retransmitted calls
					 * 2  cred refreshs
					 */

static unsigned int	svcrcinfo[9];	/* 0  repcache hits
					 * 1  repcache hits
					 * 2  uncached reqs
					 * (for pre-2.4 kernels:)
					 * 3  FH lookups
					 * 4  'anon' FHs
					 * 5  noncached non-directories
					 * 6  noncached directories
					 * 7  stale
					 */

static unsigned int	svcfhinfo[7];	/* (for kernels >= 2.4.0)
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

static const char *	nfssvrv4name[2] = {
	"null",
	"compound",
};

static const char *	nfscltv4name[32] = {
	"null",      "read",      "write",   "commit",      "open",        "open_conf",
	"open_noat", "open_dgrd", "close",   "setattr",     "fsinfo",      "renew",
	"setclntid", "confirm",   "lock",
	"lockt",     "locku",     "access",  "getattr",     "lookup",      "lookup_root",
	"remove",    "rename",    "link",    "symlink",     "create",      "pathconf",
	"statfs",    "readlink",  "readdir", "server_caps", "delegreturn",
};

typedef struct statinfo {
	char		*tag;
	int		nrvals;
	unsigned int *	valptr;
} statinfo;

#define STRUCTSIZE(x)   sizeof(x)/sizeof(*x)

static statinfo		svcinfo[] = {
	{ "net",        STRUCTSIZE(svcnetinfo), svcnetinfo },
	{ "rpc",        STRUCTSIZE(svcrpcinfo), svcrpcinfo },
	{ "rc",         STRUCTSIZE(svcrcinfo),  svcrcinfo  },
	{ "fh",         STRUCTSIZE(svcfhinfo),  svcfhinfo  },
	{ "proc2",      STRUCTSIZE(svcv2info),  svcv2info  },
	{ "proc3",      STRUCTSIZE(svcv3info),  svcv3info  },
	{ "proc4",      STRUCTSIZE(svcv4info),  svcv4info  },
	{ NULL,         0,                      NULL       }
};

static statinfo		cltinfo[] = {
	{ "net",        STRUCTSIZE(cltnetinfo), cltnetinfo },
	{ "rpc",        STRUCTSIZE(cltrpcinfo), cltrpcinfo },
	{ "proc2",      STRUCTSIZE(cltv2info),  cltv2info  },
	{ "proc3",      STRUCTSIZE(cltv3info),  cltv3info  },
	{ "proc4",      STRUCTSIZE(cltv4info),  cltv4info  },
	{ NULL,         0,                      NULL       }
};

static void		print_numbers(const char *, unsigned int *,
					unsigned int);
static void		print_callstats(const char *, const char **,
					unsigned int *, unsigned int);
static int		parse_statfile(const char *, struct statinfo *);

static statinfo		*get_stat_info(const char *, struct statinfo *);

static int             mounts(const char *);

#define PRNT_CALLS	0x0001
#define PRNT_RPC	0x0002
#define PRNT_NET	0x0004
#define PRNT_FH		0x0008
#define PRNT_RC		0x0010
#define PRNT_AUTO	0x1000
#define PRNT_V2		0x2000
#define PRNT_V3		0x4000
#define PRNT_V4		0x8000
#define PRNT_ALL	0x0fff

int versions[] = {
	PRNT_V2,
	PRNT_V3,
	PRNT_V4
};

void usage(char *name)
{
	printf("Usage: %s [OPTION]...\n\
\n\
  -m, --mounted\t\tShow statistics on mounted NFS filesystems\n\
  -c, --client\t\tShow NFS client statistics\n\
  -s, --server\t\tShow NFS server statistics\n\
  -2\t\t\tShow NFS version 2 statistics\n\
  -3\t\t\tShow NFS version 3 statistics\n\
  -4\t\t\tShow NFS version 4 statistics\n\
  -o [facility]\t\tShow statistics on particular facilities.\n\
     nfs\tNFS protocol information\n\
     rpc\tGeneral RPC information\n\
     net\tNetwork layer statistics\n\
     fh\t\tUsage information on the server's file handle cache\n\
     rc\t\tUsage information on the server's request reply cache\n\
     all\tSelect all of the above\n\
  -v, --verbose, --all\tSame as '-o all'\n\
  -r, --rpc\t\tShow RPC statistics\n\
  -n, --nfs\t\tShow NFS statistics\n\
  --version\t\tShow program version\n\
  --help\t\tWhat you just did\n\
\n", name);
	exit(0);
}

static struct option longopts[] =
{
	{ "acl", 0, 0, 'a' },
	{ "all", 0, 0, 'v' },
	{ "auto", 0, 0, '\3' },
	{ "client", 0, 0, 'c' },
	{ "mounts", 0, 0, 'm' },
	{ "nfs", 0, 0, 'n' },
	{ "rpc", 0, 0, 'r' },
	{ "server", 0, 0, 's' },
	{ "verbose", 0, 0, 'v' },
	{ "zero", 0, 0, 'z' },
	{ "help", 0, 0, '\1' },
	{ "version", 0, 0, '\2' },
	{ NULL, 0, 0, 0 }
};

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
	char           *progname;
 
	if ((progname = strrchr(argv[0], '/')))
		progname++;
	else
		progname = argv[0];

	while ((c = getopt_long(argc, argv, "234acmno:vrsz\1\2", longopts, NULL)) != EOF) {
		switch (c) {
		case 'a':
			fprintf(stderr, "nfsstat: nfs acls are not yet supported.\n");
			return -1;
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
			else if (!strcmp(optarg, "all"))
				opt_prt |= PRNT_CALLS | PRNT_RPC | PRNT_NET | PRNT_RC | PRNT_FH;
			else {
				fprintf(stderr, "nfsstat: unknown category: "
						"%s\n", optarg);
				return 2;
			}
			break;
		case '2':
		case '3':
		case '4':
			opt_prt |= versions[c - '2'];
			break;
		case 'v':
			opt_all = 1;
			break;
		case '\3':
			opt_prt |= PRNT_AUTO;
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
		case 'm':
			return mounts(MOUNTSFILE);
		case '\1':
			usage(progname);
			return 0;
		case '\2':
			fprintf(stdout, "nfsstat: " VERSION "\n");
			return 0;
		default:
			printf("Try `%s --help' for more information.\n", progname);
			return -1;
		}
	}

	if (opt_all) {
		opt_srv = opt_clt = 1;
		opt_prt |= PRNT_ALL;
	}
	if (!(opt_srv + opt_clt))
		opt_srv = opt_clt = 1;
	if (!(opt_prt & 0xfff)) {
		opt_prt |= PRNT_CALLS + PRNT_RPC;
	}
	if (!(opt_prt & 0xe000)) {
		opt_prt |= PRNT_AUTO;
	}
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
			printf("\n");
		}
		if (opt_prt & PRNT_RPC) {
			print_numbers(
			"Server rpc stats:\n"
			"calls      badcalls   badauth    badclnt    xdrcall\n",
			svcrpcinfo, 5
			);
			printf("\n");
		}
		if (opt_prt & PRNT_RC) {
			print_numbers(
			"Server reply cache:\n"
			"hits       misses     nocache\n",
			svcrcinfo, 3
			);
			printf("\n");
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
					"lookup     anon       ncachedir  ncachedir  stale\n",
					svcfhinfo + 1, 5);
			} else					/* < 2.4 */
				print_numbers(
					"Server file handle cache:\n"
					"lookup     anon       ncachedir  ncachedir  stale\n",
					svcrcinfo + 3, 5);
			printf("\n");
		}
		if (opt_prt & PRNT_CALLS) {
			if ((opt_prt & PRNT_V2) || ((opt_prt & PRNT_AUTO) && svcv2info[0] && svcv2info[svcv2info[0]+1] != svcv2info[0]))
				print_callstats(
				"Server nfs v2:\n",
				    nfsv2name, svcv2info + 1, sizeof(nfsv2name)/sizeof(char *)
				);
			if ((opt_prt & PRNT_V3) || ((opt_prt & PRNT_AUTO) && svcv3info[0] && svcv3info[svcv3info[0]+1] != svcv3info[0]))
				print_callstats(
				"Server nfs v3:\n",
				nfsv3name, svcv3info + 1, sizeof(nfsv3name)/sizeof(char *)
				);
			if ((opt_prt & PRNT_V4) || ((opt_prt & PRNT_AUTO) && svcv4info[0] && svcv4info[svcv4info[0]+1] != svcv4info[0]))
				print_callstats(
				"Server nfs v4:\n",
				nfssvrv4name, svcv4info + 1, sizeof(nfssvrv4name)/sizeof(char *)
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
			printf("\n");
		}
		if (opt_prt & PRNT_RPC) {
			print_numbers(
			"Client rpc stats:\n"
			"calls      retrans    authrefrsh\n",
			cltrpcinfo, 3
			);
			printf("\n");
		}
		if (opt_prt & PRNT_CALLS) {
			if ((opt_prt & PRNT_V2) || ((opt_prt & PRNT_AUTO) && cltv2info[0] && cltv2info[cltv2info[0]+1] != cltv2info[0]))
				print_callstats(
				"Client nfs v2:\n",
				nfsv2name, cltv2info + 1,  sizeof(nfsv2name)/sizeof(char *)
				);
			if ((opt_prt & PRNT_V3) || ((opt_prt & PRNT_AUTO) && cltv3info[0] && cltv3info[cltv3info[0]+1] != cltv3info[0]))
				print_callstats(
				"Client nfs v3:\n",
				nfsv3name, cltv3info + 1, sizeof(nfsv3name)/sizeof(char *)
				);
			if ((opt_prt & PRNT_V4) || ((opt_prt & PRNT_AUTO) && cltv4info[0] && cltv4info[cltv4info[0]+1] != cltv4info[0]))
				print_callstats(
				"Client nfs v4:\n",
				nfscltv4name, cltv4info + 1,  sizeof(nfscltv4name)/sizeof(char *)
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
			printf("%-13s", names[i+j]);
		printf("\n");
		for (j = 0; j < 6 && i + j < nr; j++) {
			pct = ((unsigned long long) info[i+j]*100)/total;
			printf("%-8d%3llu%% ", info[i+j], pct);
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
		unsigned int    i, cnt;
		unsigned int	total = 0;

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
			total += ip->valptr[i];
		}
		ip->valptr[i] = total;
	}

	fclose(fp);
	return 1;
}

static int
mounts(const char *name)
{
	char	buffer[4096], *next;
	FILE	*fp;

	/* Being unable to read e.g. the nfsd stats file shouldn't
	 * be a fatal error -- it usually means the module isn't loaded.
	 */
	if ((fp = fopen(name, "r")) == NULL) {
		fprintf(stderr, "Warning: %s: %m\n", name);
		return 0;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		char	      *line = buffer;
		char          *device, *mount, *type, *flags;

		if ((next = strchr(line, '\n')) != NULL)
			*next = '\0';

		if (!(device = strtok(line, " \t")))
			continue;

		if (!(mount = strtok(NULL, " \t")))
			continue;

		if (!(type = strtok(NULL, " \t")))
			continue;

		if (strcmp(type, "nfs")) {
		    continue;
		}

		if (!(flags = strtok(NULL, " \t")))
			continue;

		printf("%s from %s\n", mount, device);
		printf(" Flags:\t%s\n", flags);
		printf("\n");

		continue;
	}

	fclose(fp);
	return 1;
}
