/*
 * Get or set RPC debug flags.
 *
 * I would have loved to write this without recourse to the sysctl
 * interface, but the only plausible approach (reading and writing
 * /dev/kmem at the offsets indicated by the *_debug symbols from
 * /proc/ksyms) didn't work, because /dev/kmem doesn't translate virtual
 * addresses on write. Unfortunately, modules are stuffed into memory
 * allocated via vmalloc.
 *
 * Copyright (C) 1996, Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <nfs/debug.h>
#include "nfslib.h"

static int		verbose = 0;
static int		memfd;
static off_t		flagpos;

static void		find_offset(char *module);
static unsigned int	find_flag(char **module, char *name);
static unsigned int	get_flags(void);
static void		set_flags(unsigned int value);
static void		print_flags(char *module, unsigned int flags);
static void		usage(int excode);

int
main(int argc, char **argv)
{
	int		opt_s = 0,
			opt_c = 0;
	unsigned int	flags = 0, oflags;
	char *		module = NULL;
	int		c;

	while ((c = getopt(argc, argv, "chm:sv")) != EOF) {
		switch (c) {
		case 'c':
			opt_c = 1;
			break;
		case 'h':
			usage(0);
		case 'm':
			module = optarg;
			break;
		case 's':
			opt_s = 1;
			break;
		case 'v':
			verbose++;
			break;
		default:
			fprintf(stderr, "rpcdebug: unknown option -%c\n",
						optopt);
			usage(1);
		}
	}

	if (opt_c + opt_s > 1) {
		fprintf(stderr, "You can use at most one of -c and -s\n");
		usage(1);
	}

	if (argc == optind) {
		flags = ~(unsigned int) 0;
	} else {
		for (; optind < argc; optind++) {
			unsigned int	temp;

			if (!(temp = find_flag(&module, argv[optind]))) {
				fprintf(stderr, "rpcdebug: unknown flag %s\n",
							argv[optind]);
				exit(1);
			}
			flags |= temp;
		}
	}

	if (!module) {
		fprintf(stderr, "rpcdebug: no module name specified, and "
				"could not be inferred.\n");
		usage(1);
	}

	if ((memfd = open("/dev/kmem", O_RDWR)) < 0) {
		perror("can't open /dev/mem");
		exit(1);
	}

	find_offset(module);

	oflags = get_flags();

	if (opt_c) {
		set_flags(oflags & ~flags);
	} else if (opt_s) {
		set_flags(oflags | flags);
	} else {
		print_flags(module, oflags);
	}

	close(memfd);
	return 0;
}

#define FLAG(mname, fname)	\
      { #mname, #fname, mname##DBG_##fname }

static struct flagmap {
	char *		module;
	char *		name;
	unsigned int	value;
}			flagmap[] = {
	/* rpc */
	FLAG(RPC,	XPRT),
	FLAG(RPC,	CALL),
	FLAG(RPC,	TYPES),
	FLAG(RPC,	NFS),
	FLAG(RPC,	AUTH),
	FLAG(RPC,	PMAP),
	FLAG(RPC,	SCHED),
	FLAG(RPC,	SVCSOCK),
	FLAG(RPC,	SVCDSP),
	FLAG(RPC,	MISC),
	FLAG(RPC,	ALL),

	/* nfs */
	/* currently handled by RPCDBG_NFS */

	/* nfsd */
	FLAG(NFSD,	SOCK),
	FLAG(NFSD,	FH),
	FLAG(NFSD,	EXPORT),
	FLAG(NFSD,	SVC),
	FLAG(NFSD,	PROC),
	FLAG(NFSD,	FILEOP),
	FLAG(NFSD,	AUTH),
	FLAG(NFSD,	REPCACHE),
	FLAG(NFSD,	XDR),
	FLAG(NFSD,	LOCKD),
	FLAG(NFSD,	ALL),

	/* lockd */
	FLAG(NLM,	SVC),
	FLAG(NLM,	CLIENT),
	FLAG(NLM,	CLNTLOCK),
	FLAG(NLM,	SVCLOCK),
	FLAG(NLM,	MONITOR),
	FLAG(NLM,	CLNTSUBS),
	FLAG(NLM,	SVCSUBS),
	FLAG(NLM,	ALL),

      { NULL,		NULL,		0 }
};

static unsigned int
find_flag(char **module, char *name)
{
	char		*mod = *module;
	unsigned int	value = 0;
	int		i;

	for (i = 0; flagmap[i].module; i++) {
		if ((mod && strcasecmp(mod, flagmap[i].module))
		 || strcasecmp(name, flagmap[i].name))
			continue;
		if (value) {
			fprintf(stderr,
				"rpcdebug: ambiguous symbol name %s.\n"
				"This name is used by more than one module, "
				"please specify the module name using\n"
				"the -m option.\n",
				name);
			usage(1);
		}
		value = flagmap[i].value;
		if (*module)
			return value;
		mod = flagmap[i].module;
	}

	*module = mod;
	return value;
}

static unsigned int
get_flags(void)
{
	unsigned int	value;
	int		count;

	if (lseek(memfd, flagpos, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}
	if ((count = read(memfd, &value, sizeof(value))) < 0) {
		perror("read");
		exit(1);
	}
	if (count != sizeof(value)) {
		fprintf(stderr, "read failed (only %d bytes read)\n",
				count);
		exit(1);
	}
	if (verbose)
		printf("getting flags 0x%x\n", value);
	return value;
}

static void
set_flags(unsigned int value)
{
	int	count;

	if (verbose)
		printf("setting flags 0x%x\n", value);
	if (lseek(memfd, flagpos, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}
	if ((count = write(memfd, &value, sizeof(value))) < 0) {
		perror("write");
		exit(1);
	}
	if (count != sizeof(value)) {
		fprintf(stderr, "write failed (only %d bytes written)\n",
				count);
		exit(1);
	}
}

static void
find_offset(char *module)
{
	char	buffer[512], *sp;
	char	symbol[64];
	FILE	*fp;
	int	len;

	len = sprintf(symbol, "%s_debug", module);

	if ((fp = fopen("/proc/ksyms", "r")) < 0) {
		perror("rpcdebug: can't open /proc/ksyms");
		exit(1);
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (!(sp = strchr(buffer, ' ')))
			continue;
		if (strncmp(++sp, symbol, len))
			continue;
		if (sp[len] != '\n' && sp[len] != '\t'
		 && strncmp(sp+len, "_R", 2))
			continue;
		flagpos = (unsigned long) strtol(buffer, &sp, 16);
		/* printf("position is %lx\n", flagpos); */
		if (sp && *sp == ' ')
			return;
		fprintf(stderr, "rpcdebug: weird line in /proc/ksyms: %s\n",
				buffer);
		exit(1);
	}

	fprintf(stderr, "rpcdebug: debug symbol for module %s not found.\n",
			module);
	exit(1);
}

static char *
strtolower(char *str)
{
	static char	temp[64];
	char		*sp;

	strcpy(temp, str);
	for (sp = temp; *sp; sp++)
		*sp = tolower(*sp);
	return temp;
}

static void
print_flags(char *module, unsigned int flags)
{
	char	*lastmod = NULL;
	int	i;

	if (module) {
		printf("%-10s", strtolower(module));
		if (!flags) {
			printf("<no flags set>\n");
			return;
		}
		/* printf(" <%x>", flags); */
	}

	for (i = 0; flagmap[i].module; i++) {
		if (module) {
			if (strcasecmp(flagmap[i].module, module))
				continue;
		} else if (!lastmod || strcmp(lastmod, flagmap[i].module)) {
			if (lastmod)
				printf("\n");
			printf("%-10s", strtolower(flagmap[i].module));
			lastmod = flagmap[i].module;
		}
		if (!(flags & flagmap[i].value)
		 || (module && !strcasecmp(flagmap[i].name, "all")))
			continue;
		printf(" %s", strtolower(flagmap[i].name));
	}
	printf("\n");
}

static void
usage(int excode)
{
	fprintf(stderr, "usage: rpcdebug [-m module] [-cs] flags ...\n");
	if (verbose) {
		printf("\nModule     Valid flags\n");
		print_flags(NULL, ~(unsigned int) 0);
	}
	exit (excode);
}

