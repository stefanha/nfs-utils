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
#include <string.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include "statd.h"
#include "version.h"

/* Socket operations */
#include <sys/types.h>
#include <sys/socket.h>


short int restart = 0;
int	_rpcpmstart = 0;	/* flags for tirpc rpcgen */
int	_rpcfdtype = 0;
int	_rpcsvcdirty = 0;
int	run_mode = 0;		/* foreground logging mode */

/* LH - I had these local to main, but it seemed silly to have 
 * two copies of each - one in main(), one static in log.c... 
 * It also eliminates the 256-char static in log.c */
char *name_p = NULL;
char *version_p = NULL;

extern void sm_prog_1 (struct svc_req *, register SVCXPRT *);

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
	/* future: IP aliasing
	if (run_mode & MODE_NOTIFY_ONLY)
	{
		strcat(buf,"Notify-Only ");
	} */
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
	fprintf(stderr,"      -h, -?       Print this help screen.\n");
	fprintf(stderr,"      -F           Foreground (no-daemon mode)\n");
	fprintf(stderr,"      -d           Verbose logging to stderr.  Foreground mode only.\n");
	fprintf(stderr,"      -V           Display version information and exit.\n");
}

/* 
 * Entry routine/main loop.
 */
int main (int argc, char **argv)
{
	extern char *optarg;
	int pid;
	int arg;
	
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
	
	/* Process command line switches */
	while ((arg = getopt(argc, argv, "h?VFd")) >= 0) {
		switch (arg) {
			case 'V':	/* Version */
				printf("%s version %s\n",name_p,version_p);
				exit(0);
			case 'F':	/* Foreground/nodaemon mode */
				run_mode |= MODE_NODAEMON;
				break;
			case 'd':	/* No daemon only - log to stderr */
				run_mode |= MODE_LOG_STDERR;
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

	if (!(run_mode & MODE_NODAEMON)) {
		run_mode &= ~MODE_LOG_STDERR;	/* Never log to console in
						   daemon mode. */
	}

	log_init (name_p,version_p);

	log_modes();

#ifdef SIMULATIONS
	if (argc > 1)
		/* LH - I _really_ need to update simulator... */
		simulator (--argc, ++argv);	/* simulator() does exit() */
#endif
	
	if (!(run_mode & MODE_NODAEMON)) {
		int filedes;

		if ((pid = fork ()) < 0) {
			perror ("Could not fork");
			exit (1);
		} else if (pid != 0) {
			/* Parent. */
			exit (0);
		}
		/* Child.	*/
		setsid ();
		chdir (DIR_BASE);

		for (filedes = 0; filedes < sysconf (_SC_OPEN_MAX); filedes++) {
			close (filedes);
		}
	}

	/* Child. */
	signal (SIGHUP, killer);
	signal (SIGINT, killer);
	signal (SIGTERM, killer);
	/* WARNING: the following works on Linux and SysV, but not BSD! */
	signal(SIGCHLD, SIG_IGN);

	for (;;) {
		pmap_unset (SM_PROG, SM_VERS);
		change_state ();
		shuffle_dirs ();	/* Move directory names around */
		notify_hosts ();	/* Send out notify requests */
		++restart;

		/* future: IP aliasing 
		if (!(run_mode & MODE_NOTIFY_ONLY)) {
			do_regist (SM_PROG, sm_prog_1);
		} */
		do_regist(SM_PROG,sm_prog_1);

		/*
		 * Handle incoming requests:  SM_NOTIFY socket requests, as
		 * well as callbacks from lockd.
		 */
		my_svc_run();	/* I rolled my own, Olaf made it better... */
	}
	return 0;
}


/*
 * Register services.
 */
void do_regist(u_long prog, void (*sm_prog_1)())
{
	SVCXPRT		*transp;

	if ((transp = svcudp_create(RPC_ANYSOCK)) == NULL)
		die("cannot create udp service.");

	if (!svc_register(transp, prog, SM_VERS, sm_prog_1, IPPROTO_UDP))
		die("unable to register (SM_PROG, SM_VERS, udp).");

	if ((transp = svctcp_create(RPC_ANYSOCK, 0, 0)) == NULL)
		die("cannot create tcp service.");

	if (!svc_register(transp, prog, SM_VERS, sm_prog_1, IPPROTO_TCP))
		die("unable to register (SM_PROG, SM_VERS, tcp).");
}
