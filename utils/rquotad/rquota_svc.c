/*
 * QUOTA    An implementation of the diskquota system for the LINUX
 *          operating system. QUOTA is implemented using the BSD systemcall
 *          interface as the means of communication with the user level.
 *          Should work for all filesystems because of integration into the
 *          VFS layer of the operating system.
 *          This is based on the Melbourne quota system wich uses both user and
 *          group quota files.
 *
 *          This part accepts the rquota rpc-requests.
 *
 * Version: $Id: rquota_svc.c,v 2.6 1996/11/17 16:59:46 mvw Exp mvw $
 *
 * Author:  Marco van Wieringen <mvw@planets.elm.net>
 *
 *          This program is free software; you can redistribute it and/or
 *          modify it under the terms of the GNU General Public License
 *          as published by the Free Software Foundation; either version
 *          2 of the License, or (at your option) any later version.
 */
#include "config.h"

#ifdef HAVE_TCP_WRAPPER
#include "tcpwrapper.h"
#endif

#include <unistd.h>
#include <errno.h>
#include <rpc/rpc.h>
#include "rquota.h"
#include <stdlib.h>
#include <rpc/pmap_clnt.h>
#include <string.h>
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <syslog.h>
#include <signal.h>
#include <getopt.h>
#include <rpcmisc.h>

#ifdef __STDC__
#define SIG_PF void(*)(int)
#endif

extern getquota_rslt *rquotaproc_getquota_1(getquota_args *argp,
					    struct svc_req *rqstp);
extern getquota_rslt *rquotaproc_getactivequota_1(getquota_args *argp,
					          struct svc_req *rqstp);
extern getquota_rslt *rquotaproc_getquota_2(ext_getquota_args *argp,
					    struct svc_req *rqstp);
extern getquota_rslt *rquotaproc_getactivequota_2(ext_getquota_args *argp,
						  struct svc_req *rqstp);

static struct option longopts[] =
{
        { "help", 0, 0, 'h' },
        { "version", 0, 0, 'v' },
        { "port", 1, 0, 'p' },
        { NULL, 0, 0, 0 }
};

/*
 * Global authentication credentials.
 */
struct authunix_parms *unix_cred;

static void rquotaprog_1(struct svc_req *rqstp, register SVCXPRT *transp)
{
   union {
      getquota_args rquotaproc_getquota_1_arg;
      getquota_args rquotaproc_getactivequota_1_arg;
   } argument;
   char *result;
   xdrproc_t xdr_argument, xdr_result;
   char *(*local)(char *, struct svc_req *);

#ifdef HAVE_TCP_WRAPPER
   /* remote host authorization check */
   if (!check_default("rquotad", svc_getcaller(transp),
		      rqstp->rq_proc, RQUOTAPROG)) {
         svcerr_auth (transp, AUTH_FAILED);
         return;
   }
#endif

   /*
    * Don't bother authentication for NULLPROC.
    */
   if (rqstp->rq_proc == NULLPROC) {
      (void) svc_sendreply(transp, (xdrproc_t) xdr_void, (char *)NULL);
      return;
   }

   /*
    * First get authentication.
    */
   switch (rqstp->rq_cred.oa_flavor) {
      case AUTH_UNIX:
         unix_cred = (struct authunix_parms *)rqstp->rq_clntcred;
         break;
      case AUTH_NULL:
      default:
         svcerr_weakauth(transp);
         return;
   }

   switch (rqstp->rq_proc) {
      case RQUOTAPROC_GETQUOTA:
         xdr_argument = (xdrproc_t) xdr_getquota_args;
         xdr_result = (xdrproc_t) xdr_getquota_rslt;
         local = (char *(*)(char *, struct svc_req *)) rquotaproc_getquota_1;
         break;

      case RQUOTAPROC_GETACTIVEQUOTA:
         xdr_argument = (xdrproc_t) xdr_getquota_args;
         xdr_result = (xdrproc_t) xdr_getquota_rslt;
         local = (char *(*)(char *, struct svc_req *)) rquotaproc_getactivequota_1;
         break;

      default:
         svcerr_noproc(transp);
         return;
   }

   (void) memset((char *)&argument, 0, sizeof (argument));
   if (!svc_getargs(transp, xdr_argument, (caddr_t) &argument)) {
      svcerr_decode(transp);
      return;
   }
   result = (*local)((char *)&argument, rqstp);
   if (result != NULL && !svc_sendreply(transp, xdr_result, result)) {
      svcerr_systemerr(transp);
   }

   if (!svc_freeargs(transp, xdr_argument, (caddr_t) &argument)) {
      syslog(LOG_ERR, "unable to free arguments");
      exit(1);
   }
   return;
}

static void rquotaprog_2(struct svc_req *rqstp, register SVCXPRT *transp)
{
   union {
      ext_getquota_args rquotaproc_getquota_2_arg;
      ext_getquota_args rquotaproc_getactivequota_2_arg;
   } argument;
   char *result;
   xdrproc_t xdr_argument, xdr_result;
   char *(*local)(char *, struct svc_req *);

#ifdef HAVE_TCP_WRAPPER
   /* remote host authorization check */
   if (!check_default("rquotad", svc_getcaller(transp),
		      rqstp->rq_proc, RQUOTAPROG)) {
         svcerr_auth (transp, AUTH_FAILED);
         return;
   }
#endif

   /*
    * Don't bother authentication for NULLPROC.
    */
   if (rqstp->rq_proc == NULLPROC) {
      (void) svc_sendreply(transp, (xdrproc_t) xdr_void, (char *)NULL);
      return;
   }

   /*
    * First get authentication.
    */
   switch (rqstp->rq_cred.oa_flavor) {
      case AUTH_UNIX:
         unix_cred = (struct authunix_parms *)rqstp->rq_clntcred;
         break;
      case AUTH_NULL:
      default:
         svcerr_weakauth(transp);
         return;
   }

   switch (rqstp->rq_proc) {
      case RQUOTAPROC_GETQUOTA:
         xdr_argument = (xdrproc_t) xdr_ext_getquota_args;
         xdr_result = (xdrproc_t) xdr_getquota_rslt;
         local = (char *(*)(char *, struct svc_req *)) rquotaproc_getquota_2;
         break;

      case RQUOTAPROC_GETACTIVEQUOTA:
         xdr_argument = (xdrproc_t) xdr_ext_getquota_args;
         xdr_result = (xdrproc_t) xdr_getquota_rslt;
         local = (char *(*)(char *, struct svc_req *)) rquotaproc_getactivequota_2;
         break;

      default:
         svcerr_noproc(transp);
         return;
   }

   (void) memset((char *)&argument, 0, sizeof (argument));
   if (!svc_getargs(transp, xdr_argument, (caddr_t) &argument)) {
      svcerr_decode(transp);
      return;
   }
   result = (*local)((char *)&argument, rqstp);
   if (result != NULL && !svc_sendreply(transp, xdr_result, result)) {
      svcerr_systemerr(transp);
   }

   if (!svc_freeargs(transp, xdr_argument, (caddr_t) &argument)) {
      syslog(LOG_ERR, "unable to free arguments");
      exit(1);
   }
   return;
}

static void
usage(const char *prog, int n)
{
  fprintf(stderr, "Usage: %s [-p|--port port] [-h|-?|--help] [-v|--version]\n", prog);
  exit(n);
}

int main(int argc, char **argv)
{
   register SVCXPRT *transp;
   char c;
   int port = 0;

   (void) pmap_unset(RQUOTAPROG, RQUOTAVERS);
   (void) pmap_unset(RQUOTAPROG, EXT_RQUOTAVERS);

   openlog("rquota", LOG_PID, LOG_DAEMON);

   while ((c = getopt_long(argc, argv, "hp:v", longopts, NULL)) != EOF) {
     switch (c) {
     case '?':
     case 'h':
       usage(argv[0], 0);
       break;
     case 'p':
       port = atoi(optarg);
       if (port < 1 || port > 65535) {
	 fprintf(stderr, "%s: bad port number: %s\n",
		 argv[0], optarg);
	 usage(argv[0], 1);
       }
       break;
     case 'v':
       printf("rquotad %s\n", VERSION);
       exit(0);
     default:
       usage(argv[0], 1);
     }
   }

   if (chdir(NFS_STATEDIR)) {
     fprintf(stderr, "%s: chdir(%s) failed: %s\n",
	     argv [0], NFS_STATEDIR, strerror(errno));

     exit(1);
   }

   /* WARNING: the following works on Linux and SysV, but not BSD! */
   signal(SIGCHLD, SIG_IGN);

   if (port)
     transp = svcudp_create(makesock(port, IPPROTO_UDP));
   else
     transp = svcudp_create(RPC_ANYSOCK);
   if (transp == NULL) {
      syslog(LOG_ERR, "cannot create udp service.");
      exit(1);
   }
   if (!svc_register(transp, RQUOTAPROG, RQUOTAVERS, rquotaprog_1, IPPROTO_UDP)) {
      syslog(LOG_ERR, "unable to register (RQUOTAPROG, RQUOTAVERS, udp).");
      exit(1);
   }
   if (!svc_register(transp, RQUOTAPROG, EXT_RQUOTAVERS, rquotaprog_2, IPPROTO_UDP)) {
      syslog(LOG_ERR, "unable to register (RQUOTAPROG, EXT_RQUOTAVERS, udp).");
      exit(1);
   }

   daemon(1,1);
   svc_run();

   syslog(LOG_ERR, "svc_run returned");
   exit(1);
   /* NOTREACHED */
}
