/* 
 * Copyright (C) 1995, 1997-1999 Jeffrey A. Uphoff
 * Modified by Olaf Kirch, Oct. 1996.
 * Modified by H.J. Lu, 1998.
 * Modified by L. Hohberger of Mission Critical Linux, 2000.
 *
 * NSM for Linux.
 */

#include "config.h"
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include <rpcmisc.h>
#include <grp.h>
#include "statd.h"
#include "version.h"

/* Socket operations */
#include <sys/types.h>
#include <sys/socket.h>

/* Added to enable specification of state directory path at run-time
 * j_carlos_gomez@yahoo.com
 */

char * DIR_BASE = DEFAULT_DIR_BASE;

char *  SM_DIR = DEFAULT_SM_DIR;
char *  SM_BAK_DIR =  DEFAULT_SM_BAK_DIR;
char *  SM_STAT_PATH = DEFAULT_SM_STAT_PATH;

/* ----- end of state directory path stuff ------- */

short int restart = 0;
int	run_mode = 0;		/* foreground logging mode */

/* LH - I had these local to main, but it seemed silly to have 
 * two copies of each - one in main(), one static in log.c... 
 * It also eliminates the 256-char static in log.c */
char *name_p = NULL;
char *version_p = NULL;

static struct option longopts[] =
{
	{ "foreground", 0, 0, 'F' },
	{ "no-syslog", 0, 0, 'd' },
	{ "help", 0, 0, 'h' },
	{ "version", 0, 0, 'v' },
	{ "outgoing-port", 1, 0, 'o' },
	{ "port", 1, 0, 'p' },
	{ "name", 1, 0, 'n' },
	{ "state-directory-path", 1, 0, 'P' },
	{ "notify-mode", 0, 0, 'N' },
	{ NULL, 0, 0, 0 }
};

extern void sm_prog_1 (struct svc_req *, register SVCXPRT *);
extern int statd_get_socket(int port);

#ifdef SIMULATIONS
extern void simulator (int, char **);
#endif


#ifdef HAVE_TCP_WRAPPER 
#include "tcpwrapper.h"

static void 
sm_prog_1_wrapper (struct svc_req *rqstp, register SVCXPRT *transp)
{
	/* remote host authorization check */
	if (!check_default("statd", svc_getcaller(transp),
				 rqstp->rq_proc, SM_PROG)) {
		svcerr_auth (transp, AUTH_FAILED);
		return;
	}

	sm_prog_1 (rqstp, transp);
}

#define sm_prog_1 sm_prog_1_wrapper
#endif

/*
 * Signal handler.
 */
static void 
killer (int sig)
{
	log (L_FATAL, "Caught signal %d, un-registering and exiting.", sig);
	if (!(run_mode & MODE_NOTIFY_ONLY))
		pmap_unset (SM_PROG, SM_VERS);

	exit (0);
}

/*
 * Startup information.
 */
static void log_modes(void)
{
	char buf[128];		/* watch stack size... */

	/* No flags = no message */
	if (!run_mode) return;

	memset(buf,0,128);
	sprintf(buf,"Flags: ");
	if (run_mode & MODE_NODAEMON)
		strcat(buf,"No-Daemon ");
	if (run_mode & MODE_LOG_STDERR)
		strcat(buf,"Log-STDERR ");

	if (run_mode & MODE_NOTIFY_ONLY)
	{
		strcat(buf,"Notify-Only ");
	}
	log(L_WARNING,buf);
	/* future: IP aliasing
	if (run_mode & MODE_NOTIFY_ONLY)
	{
		dprintf(L_DEBUG,"Notify IP: %s",svr_addr);
	} */
}

/*
 * Since we do more than standard statd stuff, we might need to
 * help the occasional admin. 
 */
static void 
usage()
{
	fprintf(stderr,"usage: %s [options]\n", name_p);
	fprintf(stderr,"      -h, -?, --help       Print this help screen.\n");
	fprintf(stderr,"      -F, --foreground     Foreground (no-daemon mode)\n");
	fprintf(stderr,"      -d, --no-syslog      Verbose logging to stderr.  Foreground mode only.\n");
	fprintf(stderr,"      -p, --port           Port to listen on\n");
	fprintf(stderr,"      -o, --outgoing-port  Port for outgoing connections\n");
	fprintf(stderr,"      -V, -v, --version    Display version information and exit.\n");
	fprintf(stderr,"      -n, --name           Specify a local hostname.\n");
	fprintf(stderr,"      -P                   State directory path.\n");
	fprintf(stderr,"      -N                   Run in notify only mode.\n");
}

static const char *pidfile = "/var/run/rpc.statd.pid";

int pidfd = -1;
static void create_pidfile(void)
{
	FILE *fp;

	unlink(pidfile);
	fp = fopen(pidfile, "w");
	if (!fp)
		die("Opening %s failed: %s\n",
		    pidfile, strerror(errno));
	fprintf(fp, "%d\n", getpid());
	pidfd = dup(fileno(fp));
	if (fclose(fp) < 0)
		log(L_WARNING, "Flushing pid file failed.\n");
}

static void truncate_pidfile(void)
{
	if (pidfd >= 0)
		ftruncate(pidfd, 0);
}

static void drop_privs(void)
{
	struct stat st;

	if (stat(SM_DIR, &st) == -1 &&
	    stat(DIR_BASE, &st) == -1)
		st.st_uid = 0;

	if (st.st_uid == 0) {
		log(L_WARNING, "statd running as root. chown %s to choose different user\n",
		    SM_DIR);
		return;
	}
	/* better chown the pid file before dropping, as if it
	 * if over nfs we might loose access
	 */
	if (pidfd >= 0)
		fchown(pidfd, st.st_uid, st.st_gid);

	setgroups(0, NULL);
	if (setgid(st.st_gid) == -1
	    || setuid(st.st_uid) == -1) {
		log(L_ERROR, "Fail to drop privileges");
		exit(1);
	}
}

/* 
 * Entry routine/main loop.
 */
int main (int argc, char **argv)
{
	extern char *optarg;
	int pid;
	int arg;
	int port = 0, out_port = 0;

	int pipefds[2] = { -1, -1};
	char status;

	/* Default: daemon mode, no other options */
	run_mode = 0;

	/* Set the basename */
	if ((name_p = strrchr(argv[0],'/')) != NULL) {
		name_p ++;
	} else {
		name_p = argv[0];
	}

	/* Get the version */
	if ((version_p = strrchr(VERSION,' ')) != NULL) {
		version_p++;
	} else {
		version_p = VERSION;
	}
	
	/* Set hostname */
	MY_NAME = NULL;

	/* Process command line switches */
	while ((arg = getopt_long(argc, argv, "h?vVFNdn:p:o:P:", longopts, NULL)) != EOF) {
		switch (arg) {
		case 'V':	/* Version */
		case 'v':
			printf("%s version %s\n",name_p,version_p);
			exit(0);
		case 'F':	/* Foreground/nodaemon mode */
			run_mode |= MODE_NODAEMON;
			break;
		case 'N':
			run_mode |= MODE_NOTIFY_ONLY;
			break;
		case 'd':	/* No daemon only - log to stderr */
			run_mode |= MODE_LOG_STDERR;
			break;
		case 'o':
			out_port = atoi(optarg);
			if (out_port < 1 || out_port > 65535) {
				fprintf(stderr, "%s: bad port number: %s\n",
					argv[0], optarg);
				usage();
				exit(1);
			}
			break;
		case 'p':
			port = atoi(optarg);
			if (port < 1 || port > 65535) {
				fprintf(stderr, "%s: bad port number: %s\n",
					argv[0], optarg);
				usage();
				exit(1);
			}
			break;
		case 'n':	/* Specify local hostname */
			MY_NAME = xstrdup(optarg);
			break;
		case 'P':

			if ((DIR_BASE = xstrdup(optarg)) == NULL) {
				fprintf(stderr, "%s: xstrdup(%s) failed!\n",
					argv[0], optarg);
				exit(1);
			}

			SM_DIR = xmalloc(strlen(DIR_BASE) + 1 + sizeof("sm"));
			SM_BAK_DIR = xmalloc(strlen(DIR_BASE) + 1 + sizeof("sm.bak"));
			SM_STAT_PATH = xmalloc(strlen(DIR_BASE) + 1 + sizeof("state"));

			if ((SM_DIR == NULL) 
			    || (SM_BAK_DIR == NULL) 
			    || (SM_STAT_PATH == NULL)) {

				fprintf(stderr, "%s: xmalloc() failed!\n",
					argv[0]);
				exit(1);
			}
			if (DIR_BASE[strlen(DIR_BASE)-1] == '/') {
				sprintf(SM_DIR, "%ssm", DIR_BASE );
				sprintf(SM_BAK_DIR, "%ssm.bak", DIR_BASE );
				sprintf(SM_STAT_PATH, "%sstate", DIR_BASE );
			} else {
				sprintf(SM_DIR, "%s/sm", DIR_BASE );
				sprintf(SM_BAK_DIR, "%s/sm.bak", DIR_BASE );
				sprintf(SM_STAT_PATH, "%s/state", DIR_BASE );
			}
			break;
		case '?':	/* heeeeeelllllllpppp? heh */
		case 'h':
			usage();
			exit (0);
		default:	/* oh dear ... heh */
			usage();
			exit(-1);
		}
	}

	if (port == out_port && port != 0) {
		fprintf(stderr, "Listening and outgoing ports cannot be the same!\n");
		exit(-1);
	}

	if (!(run_mode & MODE_NODAEMON)) {
		run_mode &= ~MODE_LOG_STDERR;	/* Never log to console in
						   daemon mode. */
	}

#ifdef SIMULATIONS
	if (argc > 1)
		/* LH - I _really_ need to update simulator... */
		simulator (--argc, ++argv);	/* simulator() does exit() */
#endif
	
	if (!(run_mode & MODE_NODAEMON)) {
		int filedes, fdmax, tempfd;

		if (pipe(pipefds)<0) {
			perror("statd: unable to create pipe");
			exit(1);
		}
		if ((pid = fork ()) < 0) {
			perror ("statd: Could not fork");
			exit (1);
		} else if (pid != 0) {
			/* Parent.
			 * Wait for status from child.
			 */
			close(pipefds[1]);
			if (read(pipefds[0], &status, 1) != 1)
				exit(1);
			exit (0);
		}
		/* Child.	*/
		close(pipefds[0]);
		setsid ();
		if (chdir (DIR_BASE) == -1) {
			perror("statd: Could not chdir");
			exit(1);
		}

		while (pipefds[1] <= 2) {
			pipefds[1] = dup(pipefds[1]);
			if (pipefds[1]<0) {
				perror("statd: dup");
				exit(1);
			}
		}
		tempfd = open("/dev/null", O_RDWR);
		close(0); dup2(tempfd, 0);
		close(1); dup2(tempfd, 1);
		close(2); dup2(tempfd, 2);
		fdmax = sysconf (_SC_OPEN_MAX);
		for (filedes = 3; filedes < fdmax; filedes++) 
			if (filedes != pipefds[1])
				close (filedes);

	}

	/* Child. */

	log_init (name_p,version_p);

	log_modes();

	signal (SIGHUP, killer);
	signal (SIGINT, killer);
	signal (SIGTERM, killer);
	/* WARNING: the following works on Linux and SysV, but not BSD! */
	signal(SIGCHLD, SIG_IGN);

	/* initialize out_port */
	statd_get_socket(out_port);

	create_pidfile();
	atexit(truncate_pidfile);
	drop_privs();

	for (;;) {
		if (!(run_mode & MODE_NOTIFY_ONLY)) {
			/* Do not do pmap_unset() when running in notify mode.
			 * We may clear the portmapper record for a statd not
			 * running in notify mode disabling it.
			 * Juan C. Gomez j_carlos_gomez@yahoo.com
			 */
			pmap_unset (SM_PROG, SM_VERS);
		}
		change_state ();
		shuffle_dirs ();	/* Move directory names around */

		/* If we got this far, we have successfully started, so notify parent */
		if (pipefds[1] > 0) {
			status = 0;
			write(pipefds[1], &status, 1);
			close(pipefds[1]);
			pipefds[1] = -1;
		}

		notify_hosts ();	/* Send out notify requests */
		++restart;

		/* this registers both UDP and TCP services */
		if (!(run_mode & MODE_NOTIFY_ONLY)) {
			rpc_init("statd", SM_PROG, SM_VERS, sm_prog_1, port);
		} 

		/*
		 * Handle incoming requests:  SM_NOTIFY socket requests, as
		 * well as callbacks from lockd.
		 */
		my_svc_run();	/* I rolled my own, Olaf made it better... */

		if ((run_mode & MODE_NOTIFY_ONLY))
			break;			
	}
	return 0;
}
