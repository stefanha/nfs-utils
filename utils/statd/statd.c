/* 
 * Copyright (C) 1995, 1997-1999 Jeffrey A. Uphoff
 * Modified by Olaf Kirch, Oct. 1996.
 * Modified by H.J. Lu, 1998.
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

short int restart = 0;
int	_rpcpmstart = 0;	/* flags for tirpc rpcgen */
int	_rpcfdtype = 0;
int	_rpcsvcdirty = 0;

extern void sm_prog_1 (struct svc_req *, register SVCXPRT);

#ifdef SIMULATIONS
extern void simulator (int, char **);
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
 * Entry routine/main loop.
 */
int
main (int argc, char **argv)
{
  int pid;
  int foreground = 0;

  log_init (argv[0]);

  if (argc == 2 && strcmp (argv [1], "-F") == 0) {
    foreground = 1;
    argc--;
    argv++;
  }

#ifdef SIMULATIONS
  if (argc > 1)
    simulator (--argc, ++argv);	/* simulator() does exit() */
#endif
  
  if (!foreground) {
    int filedes;

    if ((pid = fork ()) < 0) {
      perror ("Could not fork");
      exit (1);
    } else if (pid != 0) {
      /* Parent. */
      exit (0);
    }
    /* Child.  */
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

  for (;;) {
    pmap_unset (SM_PROG, SM_VERS);
    change_state ();
    shuffle_dirs ();
    notify_hosts ();
    ++restart;
    do_regist (SM_PROG, sm_prog_1);
    my_svc_run ();		/* I rolled my own, Olaf made it better... */
  }
  return 0;
}


/*
 * Register services.
 */
void
do_regist(u_long prog, void (*sm_prog_1)())
/* do_regist(u_long prog, __dispatch_fn_t sm_prog_1) */
{
  SVCXPRT        *transp;

  if ((transp = svcudp_create(RPC_ANYSOCK)) == NULL)
    die("cannot create udp service.");

  if (!svc_register(transp, prog, SM_VERS, sm_prog_1, IPPROTO_UDP))
    die("unable to register (SM_PROG, SM_VERS, udp).");

  if ((transp = svctcp_create(RPC_ANYSOCK, 0, 0)) == NULL)
    die("cannot create tcp service.");

  if (!svc_register(transp, prog, SM_VERS, sm_prog_1, IPPROTO_TCP))
    die("unable to register (SM_PROG, SM_VERS, tcp).");
}
